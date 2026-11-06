package portal

const stylesheetText = `
:root { color-scheme: dark; }
* { box-sizing: border-box; }
body { margin: 0; font: 16px/1.5 system-ui, -apple-system, "Segoe UI", sans-serif;
  background: #1f1f1f; color: #e8e8e8; }
header { display: flex; align-items: center; justify-content: space-between;
  gap: 1rem; padding: .75rem 1.25rem; background: #161616; border-bottom: 1px solid #333; }
.brand { color: #fff; font-weight: 700; font-size: 1.25rem; text-decoration: none; }
.brand span { font-weight: 400; color: #aaa; }
.who { display: flex; align-items: center; gap: .75rem; }
.who form { margin: 0; }
.role { padding: .1rem .5rem; border-radius: .75rem; font-size: .8rem; background: #444; }
.role-editor { background: #1f5f2f; }
.role-viewer { background: #3a4a66; }
main { max-width: 56rem; margin: 0 auto; padding: 1.25rem; }
h1 { font-size: 1.5rem; margin: .5rem 0 1rem; }
.title-row { display: flex; align-items: center; justify-content: space-between; }
.card { background: #2a2a2a; border: 1px solid #3a3a3a; border-radius: .5rem;
  padding: 1rem; margin: 1rem 0; max-width: 40rem; }
.card.danger { border-color: #7a2a2a; }
label { display: block; margin: .5rem 0 .25rem; font-weight: 600; }
input[type=text], input[type=password], textarea { width: 100%; padding: .5rem;
  color: #fff; background: #151515; border: 1px solid #555; border-radius: .25rem;
  font: inherit; }
textarea { font-family: ui-monospace, Menlo, Consolas, monospace; }
input:focus, textarea:focus, button:focus, a:focus { outline: 2px solid #6aa9ff; outline-offset: 2px; }
button, .button { display: inline-block; padding: .5rem 1rem; color: #fff; background: #2b6cd9;
  border: 0; border-radius: .25rem; font: inherit; cursor: pointer; text-decoration: none; }
button.danger { background: #b03030; }
.secondary { background: #444; }
button.link { background: none; padding: 0; color: #9cc2ff; text-decoration: underline; }
.actions { display: flex; gap: .75rem; margin-top: 1rem; }
.hint, .meta { color: #aaa; font-size: .9rem; }
.notice { padding: .5rem .75rem; background: #1d3b27; border: 1px solid #2f6a45; border-radius: .25rem; }
.error { padding: .5rem .75rem; background: #4a1f1f; border: 1px solid #8a3a3a; border-radius: .25rem; }
table { width: 100%; border-collapse: collapse; }
th, td { text-align: left; padding: .5rem; border-bottom: 1px solid #333; vertical-align: top; }
a { color: #9cc2ff; }
.message { padding: .75rem; background: #151515; border: 1px solid #444; border-radius: .25rem;
  white-space: pre-wrap; word-break: break-word; }
`
