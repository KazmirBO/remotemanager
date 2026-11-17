//! Czytniki kart przez usługę kart systemu Windows (WinSCard, biblioteka `pcsc`). Implementuje
//! cechy z modułu `scard`; cała logika przekierowania i jej testy są tam.

use std::ffi::CString;
use std::time::Duration;

use pcsc::ffi::DWORD;
use pcsc::{
    Card, Context, Disposition, Protocols, ReaderState, Scope, ShareMode, State, Status,
    Transaction,
};

use crate::scard::{
    CardDev, CardInfo, CardOps, Code, Ctx, E_INVALID_PARAMETER, E_PROTO_MISMATCH, E_UNKNOWN_READER,
    INFINITE, Service, StateIo,
};

/// Kod błędu usługi kart; wartości biblioteki są wartościami WinSCard.
fn code(error: pcsc::Error) -> Code {
    error as u32
}

// Typ `DWORD` ma 32 bity na Windows, a 64 w pcsc-lite, na którym ten moduł sprawdzamy typami.
#[allow(clippy::useless_conversion)]
fn dword(value: u32) -> DWORD {
    value.into()
}

#[allow(clippy::unnecessary_cast, clippy::cast_possible_truncation)]
fn from_dword(value: DWORD) -> u32 {
    value as u32
}

fn disposition(value: u32) -> Disposition {
    match value {
        1 => Disposition::ResetCard,
        2 => Disposition::UnpowerCard,
        3 => Disposition::EjectCard,
        _ => Disposition::LeaveCard,
    }
}

/// Stan karty w numeracji protokołu (0 nieznany ... 6 tryb wybrany).
fn state_number(status: Status) -> u32 {
    [
        (Status::SPECIFIC, 6),
        (Status::NEGOTIABLE, 5),
        (Status::POWERED, 4),
        (Status::SWALLOWED, 3),
        (Status::PRESENT, 2),
        (Status::ABSENT, 1),
    ]
    .into_iter()
    .find(|(flag, _)| status.contains(*flag))
    .map_or(0, |(_, number)| number)
}

fn transmit_on(card: &Card, direct: bool, send: &[u8], max_recv: usize) -> Result<Vec<u8>, Code> {
    // Połączenie bezpośrednie z czytnikiem nie ma protokołu karty, a biblioteka przy takim wywołaniu
    // przerywa wątek zamiast zwrócić błąd.
    if direct {
        return Err(E_PROTO_MISMATCH);
    }
    let mut buffer = vec![0u8; max_recv];
    let len = card.transmit(send, &mut buffer).map_err(code)?.len();
    buffer.truncate(len);
    Ok(buffer)
}

fn status_of(card: &Card) -> Result<CardInfo, Code> {
    let status = card.status2_owned().map_err(code)?;
    Ok(CardInfo {
        readers: status
            .reader_names()
            .iter()
            .map(|name| name.to_string_lossy().into_owned())
            .collect(),
        state: state_number(status.status()),
        protocol: status.protocol2().map_or(0, |protocol| protocol as u32),
        atr: status.atr().to_vec(),
    })
}

/// Usługa kart tego komputera.
pub(crate) struct System;

impl Service for System {
    type Ctx = SystemCtx;

    fn establish(&self) -> Result<SystemCtx, Code> {
        Context::establish(Scope::User).map(SystemCtx).map_err(code)
    }
}

pub(crate) struct SystemCtx(Context);

impl Ctx for SystemCtx {
    type Card = SystemCard;

    fn list_readers(&self) -> Result<Vec<String>, Code> {
        let readers = self.0.list_readers_owned().map_err(code)?;
        Ok(readers
            .iter()
            .map(|name| name.to_string_lossy().into_owned())
            .collect())
    }

    fn status_change(&self, timeout_ms: u32, states: &mut [StateIo]) -> Result<(), Code> {
        let mut raw = Vec::with_capacity(states.len());
        for state in states.iter() {
            let name = CString::new(state.reader.as_str()).map_err(|_| E_UNKNOWN_READER)?;
            // Stan idzie w całości, razem z licznikiem zdarzeń w starszym słowie: bez niego Windows
            // zgłasza pseudoczytnik powiadomień jako zmieniony przy każdym wywołaniu.
            raw.push(ReaderState::new(
                name,
                State::from_bits_retain(dword(state.current)),
            ));
        }
        let timeout =
            (timeout_ms != INFINITE).then(|| Duration::from_millis(u64::from(timeout_ms)));
        let result = self.0.get_status_change(timeout, &mut raw);
        if result.is_ok() {
            for (state, raw) in states.iter_mut().zip(&raw) {
                state.event = from_dword(raw.event_state().bits()) | (raw.event_count() << 16);
                state.atr = raw.atr().to_vec();
            }
        }
        result.map_err(code)
    }

    fn cancel(&self) -> Result<(), Code> {
        self.0.cancel().map_err(code)
    }

    fn is_valid(&self) -> Result<(), Code> {
        self.0.is_valid().map_err(code)
    }

    fn connect(
        &self,
        reader: &str,
        share_mode: u32,
        protocols: u32,
    ) -> Result<(SystemCard, u32), Code> {
        let name = CString::new(reader).map_err(|_| E_UNKNOWN_READER)?;
        let share = match share_mode {
            1 => ShareMode::Exclusive,
            2 => ShareMode::Shared,
            3 => ShareMode::Direct,
            _ => return Err(E_INVALID_PARAMETER),
        };
        let card = self
            .0
            .connect(
                &name,
                share,
                Protocols::from_bits_truncate(dword(protocols)),
            )
            .map_err(code)?;
        // Biblioteka nie oddaje protokołu wybranego przy łączeniu, więc pytamy o stan karty.
        let protocol = card
            .status2_owned()
            .ok()
            .and_then(|status| status.protocol2())
            .map_or(0, |protocol| protocol as u32);
        Ok((
            SystemCard {
                card,
                direct: protocol == 0,
            },
            protocol,
        ))
    }
}

pub(crate) struct SystemCard {
    card: Card,
    /// Połączenie bez protokołu karty (tryb bezpośredni albo karta bez ustalonego protokołu).
    direct: bool,
}

impl CardOps for SystemCard {
    fn transmit(&self, send: &[u8], max_recv: usize) -> Result<Vec<u8>, Code> {
        transmit_on(&self.card, self.direct, send, max_recv)
    }

    fn status(&self) -> Result<CardInfo, Code> {
        status_of(&self.card)
    }
}

pub(crate) struct SystemTx<'a> {
    tx: Transaction<'a>,
    direct: bool,
}

impl CardOps for SystemTx<'_> {
    fn transmit(&self, send: &[u8], max_recv: usize) -> Result<Vec<u8>, Code> {
        transmit_on(&self.tx, self.direct, send, max_recv)
    }

    fn status(&self) -> Result<CardInfo, Code> {
        status_of(&self.tx)
    }
}

impl CardDev for SystemCard {
    type Tx<'a> = SystemTx<'a>;

    fn begin(&mut self) -> Result<SystemTx<'_>, Code> {
        let direct = self.direct;
        self.card
            .transaction()
            .map(|tx| SystemTx { tx, direct })
            .map_err(code)
    }

    fn end(tx: SystemTx<'_>, how: u32) -> Result<(), Code> {
        tx.tx
            .end(disposition(how))
            .map_err(|(_, error)| code(error))
    }

    fn disconnect(self, how: u32) -> Result<(), Code> {
        self.card
            .disconnect(disposition(how))
            .map_err(|(_, error)| code(error))
    }
}
