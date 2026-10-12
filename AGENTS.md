# UI interaction rules

- Use accessible in-app modals for confirmations, alerts and user input.
- Never use browser JavaScript popups (`alert`, `confirm` or `prompt`).
- Reuse the shared dialog patterns in the base template and app JavaScript.
- Preserve keyboard access, safe cancellation, focus restoration and the exact
  form action/submitter when confirming an operation.

# Live data rules

- Render changing application data, status, actions and permissions through
  permission-filtered WebSocket regions, including new pages and editors.
- Keep workspace actions on the current page; queue them through authorized HTTP
  POSTs and refresh results over WebSockets instead of reloading.
- Preserve unsaved drafts, selected options, focus/cursor and scroll positions.
  An outdated configuration editor must show a live warning and block saving
  without silently replacing its draft.
