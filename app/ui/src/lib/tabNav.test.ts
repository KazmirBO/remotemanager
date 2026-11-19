import { describe, expect, it } from 'vitest';
import { tabKeyTarget } from './tabNav';

describe('tabKeyTarget', () => {
  it('poziomo: strzałki w lewo i w prawo z zawijaniem', () => {
    expect(tabKeyTarget('ArrowRight', 0, 4, 'horizontal')).toBe(1);
    expect(tabKeyTarget('ArrowRight', 3, 4, 'horizontal')).toBe(0);
    expect(tabKeyTarget('ArrowLeft', 0, 4, 'horizontal')).toBe(3);
    expect(tabKeyTarget('ArrowLeft', 2, 4, 'horizontal')).toBe(1);
  });
  it('pionowo: strzałki w górę i w dół z zawijaniem', () => {
    expect(tabKeyTarget('ArrowDown', 1, 3, 'vertical')).toBe(2);
    expect(tabKeyTarget('ArrowDown', 2, 3, 'vertical')).toBe(0);
    expect(tabKeyTarget('ArrowUp', 0, 3, 'vertical')).toBe(2);
  });
  it('strzałki drugiej osi nie działają', () => {
    expect(tabKeyTarget('ArrowRight', 0, 3, 'vertical')).toBeNull();
    expect(tabKeyTarget('ArrowDown', 0, 3, 'horizontal')).toBeNull();
  });
  it('Home i End', () => {
    expect(tabKeyTarget('Home', 2, 5, 'horizontal')).toBe(0);
    expect(tabKeyTarget('End', 0, 5, 'vertical')).toBe(4);
  });
  it('inne klawisze i pusta lista dają null', () => {
    expect(tabKeyTarget('Enter', 0, 3, 'horizontal')).toBeNull();
    expect(tabKeyTarget('Home', 0, 0, 'horizontal')).toBeNull();
  });
});
