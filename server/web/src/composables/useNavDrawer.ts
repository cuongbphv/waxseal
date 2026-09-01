/* Whether the sidebar is showing as an overlay, on the widths where it is one.
 *
 * Above the compact breakpoint the sidebar is simply part of the layout and
 * this flag is ignored, so nothing has to keep the two in sync. The flag exists
 * only for the widths where the nav would otherwise take two thirds of the
 * screen.
 */

import { readonly, shallowRef } from 'vue'

const open = shallowRef(false)

export const drawerOpen = readonly(open)

export function openDrawer(): void {
  open.value = true
}

export function closeDrawer(): void {
  open.value = false
}

export function toggleDrawer(): void {
  open.value = !open.value
}
