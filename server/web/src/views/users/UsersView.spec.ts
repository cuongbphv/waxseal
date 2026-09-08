import { beforeEach, describe, expect, it, vi } from 'vitest'
import { ref, shallowRef } from 'vue'
import { resetServerFactsForTests, meta, principal } from '@/services/serverFacts'
import { clearToken, setToken } from '@/lib/session'
import { mountView } from '@/test/viewHarness'
import UsersView from './UsersView.vue'

vi.mock('@/lib/i18n', () => ({
  useI18n: () => ({
    lang: ref('en'),
    t: (key: string) => key,
    setLang: vi.fn(),
  }),
}))

vi.mock('@/composables/useOperators', () => ({
  useOperators: () => ({
    operators: {
      data: shallowRef([]),
      pending: ref(false),
      started: ref(true),
      error: shallowRef(null),
      run: vi.fn(),
    },
    creating: ref(false),
    createError: shallowRef(null),
    created: shallowRef(null),
    invite: vi.fn(),
  }),
}))

describe('UsersView AuthNeeded gating', () => {
  beforeEach(() => {
    resetServerFactsForTests()
    clearToken()
  })

  it('does not render AuthNeeded when a credential is already in hand', () => {
    meta.value = {
      version: '0.1.5',
      write_auth: 'bearer_required',
      witness_auth: 'open',
      public_read: '/public/v1',
    }
    setToken('test-token')
    principal.value = {
      username: 'alice',
      is_operator: true,
      role: 'admin',
      scopes: [],
      key_id: 'k1',
    }
    const wrapper = mountView(UsersView)
    expect(wrapper.text()).not.toContain('authNeededBody')
  })

  it('renders AuthNeeded when the server requires a bearer and none is set', () => {
    meta.value = {
      version: '0.1.5',
      write_auth: 'bearer_required',
      witness_auth: 'open',
      public_read: '/public/v1',
    }
    const wrapper = mountView(UsersView)
    expect(wrapper.text()).toContain('authNeededBody')
  })
})
