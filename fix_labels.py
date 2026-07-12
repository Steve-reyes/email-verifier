# -*- coding: utf-8 -*-
with open('/root/email-verifier/templates/index.html', 'r', encoding='utf-8') as f:
    html = f.read()

# Add helper function after lastResults
helper = """function smtpLabel(code, catchAll) {
  if (code === 'quick' || code === '' || !code) return '\U0001F50D DNS Only';
  if (code === 'SKIPPED') return '\u23ED Skipped';
  if (code && code.startsWith('ERR:')) return '\u274C Error';
  if (catchAll && catchAll.catch_all) return '\u26A0\uFE0F Catch-All';
  if (code === '250' || (code && code.startsWith('250 '))) return '\u2705 Deliverable';
  if (code && code.startsWith('550')) return '\u274C Bounce';
  if (code && code.startsWith('450')) return '\u23F3 Temp Fail';
  if (code && code.startsWith('554')) return '\u274C Rejected';
  if (code && code.startsWith('4')) return '\u23F3 Temp Fail';
  if (code && code.startsWith('5')) return '\u274C Rejected';
  return code;
}
"""

insert_point = html.find('let lastResults')
if insert_point >= 0:
    insert_point = html.find(';', insert_point) + 1
    html = html[:insert_point] + helper + html[insert_point:]
    print("Helper inserted")
else:
    print("let lastResults not found")

# Replace SMTP display in renderResults
old1 = "'+(r.smtp_status||'-')+'"
new1 = "'+smtpLabel(r.smtp_status, r.catch_all)+'"
if old1 in html:
    html = html.replace(old1, new1)
    print("1. RenderResults replaced")
else:
    print("1. Not found")

# Replace SMTP display in toggleDetail
old2 = "const smtp = vr && vr.smtp_status ? vr.smtp_status.replace(/^5\\d\\d\\s/,'') : (vr && vr.valid !== null ? 'quick' : '-')"
new2 = "const smtp = vr && vr.smtp_status ? smtpLabel(vr.smtp_status, vr.catch_all) : (vr && vr.valid !== null ? smtpLabel('quick') : '-')"
if old2 in html:
    html = html.replace(old2, new2)
    print("2. ToggleDetail replaced")
else:
    print("2. Not found, trying to locate...")
    idx = html.find('const smtp = vr')
    if idx >= 0: print("  Found:", repr(html[idx:idx+150]))

# Also fix auto-SMTP toast to allow HTML
html = html.replace(
    "toast('\u2705 SMTP check complete', 'success')",
    "toast('\u2705 SMTP check complete', 'success')"
)

with open('/root/email-verifier/templates/index.html', 'w', encoding='utf-8') as f:
    f.write(html)
print("DONE")
