import { describe, expect, it } from 'vitest';
import { createAcker } from './sshAck';

function setup(threshold = 100) {
  const sent: number[] = [];
  const state = { hidden: false };
  const acker = createAcker((n) => sent.push(n), () => state.hidden, threshold);
  const total = () => sent.reduce((a, b) => a + b, 0);
  return { sent, state, acker, total };
}

describe('createAcker', () => {
  it('widoczny dokument potwierdza po przetworzeniu i dopiero od progu', () => {
    const { sent, acker } = setup();
    acker.ready();
    const d1 = acker.receive(60);
    expect(sent).toEqual([]);
    d1();
    expect(sent).toEqual([]);
    const d2 = acker.receive(60);
    d2();
    expect(sent).toEqual([120]);
  });
  it('ukryty dokument potwierdza od razu, a późne wywołanie zwrotne nie liczy bajtów drugi raz', () => {
    const { sent, state, acker, total } = setup();
    acker.ready();
    state.hidden = true;
    const done = acker.receive(10);
    expect(sent).toEqual([10]);
    done();
    done();
    expect(total()).toBe(10);
  });
  it('ukrycie w trakcie przetwarzania potwierdza czekające porcje raz', () => {
    const { sent, state, acker, total } = setup();
    acker.ready();
    const d1 = acker.receive(30);
    const d2 = acker.receive(40);
    d1();
    state.hidden = true;
    acker.hide();
    expect(total()).toBe(70);
    d2();
    d1();
    expect(total()).toBe(70);
    expect(sent.length).toBeLessThanOrEqual(2);
  });
  it('dane sprzed poznania identyfikatora czekają na ready', () => {
    const { sent, state, acker } = setup();
    state.hidden = true;
    acker.receive(5);
    acker.receive(6);
    expect(sent).toEqual([]);
    acker.ready();
    expect(sent).toEqual([11]);
  });
  it('powrót do widoczności wraca do liczenia po przetworzeniu', () => {
    const { sent, state, acker } = setup(10);
    acker.ready();
    state.hidden = true;
    acker.receive(4);
    state.hidden = false;
    const d = acker.receive(12);
    expect(sent).toEqual([4]);
    d();
    expect(sent).toEqual([4, 12]);
  });
});
