/* The head of the chain currently in context, for the header pill.
 *
 * Three states, not two. The pill has to distinguish "no chain is selected"
 * from "a chain is selected and it is empty" from "here is the head", because
 * the middle one is a real fact about a real chain and rendering it the same
 * as the first would hide it.
 *
 * The trail screen publishes into this; nothing else writes it, and it clears
 * on the way out so a stale head cannot outlive the screen that knew it.
 */

import { shallowRef } from 'vue'
import type { Head } from '@/lib/api'

export type ActiveHead = Head | 'empty' | 'no-chain'

export const activeHead = shallowRef<ActiveHead>('no-chain')

export function setActiveHead(head: ActiveHead): void {
  activeHead.value = head
}

export function clearActiveHead(): void {
  activeHead.value = 'no-chain'
}
