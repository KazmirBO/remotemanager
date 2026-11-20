import { describe, expect, it } from 'vitest';
import { dropIndex, moveItem } from './tabOrder';

const tabs = ['a', 'b', 'c', 'd'];

describe('moveItem', () => {
  it('przenosi w lewo i w prawo', () => {
    expect(moveItem(tabs, 2, 1)).toEqual(['a', 'c', 'b', 'd']);
    expect(moveItem(tabs, 0, 3)).toEqual(['b', 'c', 'd', 'a']);
  });
  it('nie zmienia listy przy tym samym albo błędnym indeksie i nie rusza oryginału', () => {
    for (const [from, to] of [[1, 1], [-1, 0], [0, 4], [9, 0]]) {
      expect(moveItem(tabs, from, to)).toEqual(tabs);
    }
    expect(tabs).toEqual(['a', 'b', 'c', 'd']);
  });
});

describe('dropIndex', () => {
  const drop = (from: number, target: number, after: boolean) => moveItem(tabs, from, dropIndex(from, target, after));
  it('upuszczenie przed kartą i za kartą po prawej stronie', () => {
    expect(drop(0, 2, false)).toEqual(['b', 'a', 'c', 'd']);
    expect(drop(0, 2, true)).toEqual(['b', 'c', 'a', 'd']);
    expect(drop(0, 3, true)).toEqual(['b', 'c', 'd', 'a']);
  });
  it('upuszczenie przed kartą i za kartą po lewej stronie', () => {
    expect(drop(3, 1, false)).toEqual(['a', 'd', 'b', 'c']);
    expect(drop(3, 1, true)).toEqual(['a', 'b', 'd', 'c']);
    expect(drop(3, 0, false)).toEqual(['d', 'a', 'b', 'c']);
  });
  it('upuszczenie na siebie albo tuż obok niczego nie zmienia', () => {
    expect(drop(1, 1, false)).toEqual(tabs);
    expect(drop(1, 1, true)).toEqual(tabs);
    expect(drop(1, 0, true)).toEqual(tabs);
    expect(drop(1, 2, false)).toEqual(tabs);
  });
});
