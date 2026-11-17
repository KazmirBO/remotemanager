//! Przekierowanie kluczy bezpieczeństwa do sesji RDP (WebAuthn, [MS-RDPEWA]): kanał dynamiczny
//! `WebAuthN_Channel`, przez który zdalny pulpit prosi o operację na kluczu podłączonym do tego
//! komputera (np. YubiKey) i dostaje jej wynik.
//!
//! Protokół kanału i wykonanie operacji przez systemowe API Windows pochodzą z crate'ów
//! `ironrdp-rdpewa` i `ironrdp-rdpewa-native`, które istnieją tylko dla nowszego stosu IronRDP.
//! Reszta procesu zostaje na dotychczasowym stosie, więc ten moduł jest wyłącznie łącznikiem:
//! przekazuje dane kanału do klienta z nowszego stosu, a jego odpowiedzi zamienia na surowe bajty
//! wysyłane kanałem dynamicznym obecnego stosu. Kanał jest rejestrowany tylko dla hostów
//! z włączonym ustawieniem; bez niego sesja działa dokładnie jak dotąd.
//!
//! Serwer jest niezaufany: błędne żądanie jest pomijane z wpisem w dzienniku i nie kończy sesji,
//! a każdą operację na kluczu użytkownik potwierdza w oknie systemu.

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::mpsc::Sender;

use ironrdp::core::{Encode, EncodeResult, WriteCursor};
use ironrdp::dvc::{DvcChannelListener, DvcEncode, DvcMessage, DvcProcessor, DynamicChannelId};
use ironrdp::pdu::PduResult;
use ironrdp::svc::{ChannelFlags, SvcMessage};
use ironrdp_dvc10::DvcProcessor as _;
use ironrdp_rdpewa::{CHANNEL_NAME, RdpewaClient, RdpewaClientHandler, RdpewaResponseSender};

/// Odpowiedź gotowa po czasie: użytkownik potwierdził albo odrzucił operację w oknie systemu.
/// Pętla sesji wysyła ją kanałem o podanym identyfikatorze (`encode_reply`).
pub(crate) struct Reply {
    pub channel_id: u32,
    pub data: Vec<u8>,
}

/// Tworzy wykonawcę operacji dla nowo otwartego kanału.
pub(crate) type HandlerFactory = Box<dyn FnMut() -> Box<dyn RdpewaClientHandler> + Send>;

/// Nasłuch kanału. Windows otwiera i zamyka `WebAuthN_Channel` przy każdej operacji, więc każde
/// otwarcie dostaje świeżego klienta.
pub(crate) struct Listener {
    replies: Sender<Reply>,
    handler: HandlerFactory,
}

impl Listener {
    pub(crate) fn new(replies: Sender<Reply>, handler: HandlerFactory) -> Self {
        Self { replies, handler }
    }
}

impl DvcChannelListener for Listener {
    fn channel_name(&self) -> &str {
        CHANNEL_NAME
    }

    fn create(&mut self, _channel_id: DynamicChannelId) -> Option<Box<dyn DvcProcessor>> {
        Some(Box::new(Channel::new(
            (self.handler)(),
            self.replies.clone(),
        )))
    }
}

/// Jeden otwarty kanał: klient z nowszego stosu opakowany interfejsem obecnego.
struct Channel {
    client: RdpewaClient,
    /// Identyfikator kanału, znany od `start`; potrzebny odpowiedziom wysyłanym po czasie.
    id: Arc<AtomicU32>,
}

impl Channel {
    fn new(handler: Box<dyn RdpewaClientHandler>, replies: Sender<Reply>) -> Self {
        let id = Arc::new(AtomicU32::new(0));
        let reply_id = Arc::clone(&id);
        let client = RdpewaClient::new(handler).with_response_sender_factory(move || {
            let (id, replies) = (Arc::clone(&reply_id), replies.clone());
            RdpewaResponseSender::new(move |data| {
                // Sesja mogła się skończyć, zanim użytkownik odpowiedział: odpowiedź przepada.
                let _ = replies.send(Reply {
                    channel_id: id.load(Ordering::Acquire),
                    data,
                });
            })
        });
        Self { client, id }
    }
}

ironrdp::core::impl_as_any!(Channel);

impl DvcProcessor for Channel {
    fn channel_name(&self) -> &str {
        CHANNEL_NAME
    }

    fn start(&mut self, channel_id: u32) -> PduResult<Vec<DvcMessage>> {
        self.id.store(channel_id, Ordering::Release);
        Ok(convert(self.client.start(channel_id)))
    }

    fn process(&mut self, channel_id: u32, payload: &[u8]) -> PduResult<Vec<DvcMessage>> {
        Ok(convert(self.client.process(channel_id, payload)))
    }

    fn close(&mut self, channel_id: u32) {
        self.client.close(channel_id);
    }
}

/// Zamienia komunikaty klienta z nowszego stosu na surowe bajty dla obecnego. Błąd klienta (żądanie
/// serwera, którego nie dało się zdekodować) nie kończy sesji: trafia do dziennika, bez treści żądania.
fn convert<E: std::fmt::Display>(
    result: Result<Vec<ironrdp_dvc10::DvcMessage>, E>,
) -> Vec<DvcMessage> {
    let messages = match result {
        Ok(messages) => messages,
        Err(e) => {
            crate::log(format!("WebAuthn: pominięto żądanie serwera: {e}"));
            return Vec::new();
        }
    };
    messages
        .into_iter()
        .filter_map(|message| {
            let mut data = vec![0u8; message.size()];
            match message.encode(&mut ironrdp_core03::WriteCursor::new(&mut data)) {
                Ok(()) => Some(Box::new(Raw(data)) as DvcMessage),
                Err(e) => {
                    crate::log(format!("WebAuthn: nie udało się zakodować odpowiedzi: {e}"));
                    None
                }
            }
        })
        .collect()
}

/// Odpowiedź wysłana po czasie jako komunikaty kanału dynamicznego obecnego stosu.
pub(crate) fn encode_reply(reply: Reply) -> EncodeResult<Vec<SvcMessage>> {
    ironrdp::dvc::encode_dvc_messages(
        reply.channel_id,
        vec![Box::new(Raw(reply.data))],
        ChannelFlags::empty(),
    )
}

/// Gotowe bajty komunikatu kanału.
struct Raw(Vec<u8>);

impl Encode for Raw {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        ironrdp::core::ensure_size!(in: dst, size: self.0.len());
        dst.write_slice(&self.0);
        Ok(())
    }

    fn name(&self) -> &'static str {
        "WebAuthnRaw"
    }

    fn size(&self) -> usize {
        self.0.len()
    }
}

impl DvcEncode for Raw {}

#[cfg(test)]
mod tests {
    use std::sync::mpsc::channel;

    use ironrdp_rdpewa::{RdpewaRequest, RdpewaResponse, RpcCommand, S_OK, StubRdpewaHandler};

    use super::*;

    fn bytes(message: &DvcMessage) -> Vec<u8> {
        ironrdp::core::encode_vec(message.as_ref()).expect("kodowanie")
    }

    fn listener() -> Listener {
        let (tx, _rx) = channel();
        Listener::new(
            tx,
            Box::new(|| {
                Box::new(StubRdpewaHandler {
                    api_version: 7,
                    uvpaa: true,
                })
            }),
        )
    }

    #[test]
    fn channel_answers_api_version_through_the_old_stack() {
        let mut listener = listener();
        assert_eq!(listener.channel_name(), "WebAuthN_Channel");
        let mut channel = listener.create(5).expect("kanał");
        assert!(channel.start(5).expect("start").is_empty());

        let request = RdpewaRequest {
            command: RpcCommand::ApiVersion,
            flags: 0,
            rp_id: None,
            timeout_ms: 0,
            transaction_id: Vec::new(),
            client_data_json: None,
            webauthn_para: None,
            request_body: Vec::new(),
            raw: Default::default(),
        }
        .encode()
        .expect("żądanie");
        let out = channel.process(5, &request).expect("odpowiedź");
        assert_eq!(out.len(), 1);
        let response = RdpewaResponse::decode(&bytes(&out[0])).expect("dekodowanie");
        assert_eq!(response.hresult, S_OK);
        assert_eq!(response.payload_u32().expect("wersja"), 7);
    }

    #[test]
    fn malformed_request_is_skipped_without_ending_the_session() {
        let mut listener = listener();
        let mut channel = listener.create(1).expect("kanał");
        let out = channel
            .process(1, &[0xFF, 0x00, 0x13])
            .expect("bez błędu sesji");
        assert!(out.is_empty());
    }

    #[test]
    fn late_reply_is_encoded_for_its_channel() {
        let messages = encode_reply(Reply {
            channel_id: 9,
            data: vec![1, 2, 3],
        })
        .expect("kodowanie");
        assert_eq!(messages.len(), 1);
    }
}
