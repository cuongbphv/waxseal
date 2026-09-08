import { describe, expect, it } from 'vitest'
import { cadenceInputFromForm } from '@/services/chains'

describe('cadenceInputFromForm', () => {
  it('maps form fields onto CadenceInput without inventing M', () => {
    expect(
      cadenceInputFromForm({
        lam: '1',
        c: '2',
        w: '3',
        rho: '4',
        delta: '5',
        t_max: '6',
        m: '',
      }),
    ).toEqual({
      lam: '1',
      c: '2',
      w: '3',
      rho: '4',
      delta: '5',
      t_max: '6',
    })
  })

  it('keeps an operator-supplied M rather than substituting the CLI default', () => {
    expect(
      cadenceInputFromForm({
        lam: '1',
        c: '2',
        w: '3',
        rho: '4',
        delta: '5',
        t_max: '6',
        m: '3',
      }).m,
    ).toBe('3')
  })
})
