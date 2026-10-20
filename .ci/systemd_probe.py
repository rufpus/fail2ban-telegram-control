# SPDX-License-Identifier: MIT
"""ExecStartPre probe: run inside the production unit's actual systemd sandbox."""
from pathlib import Path
import f2btelegram as f
import f2bmanage as m

cfg = f.config()
state = m.snapshot()  # Real AF_UNIX socket, including the Python action bridge.
assert isinstance(state['bans'], list)
m.verify_scope(cfg)
with f.database() as db:
    assert db.execute("SELECT value FROM meta WHERE key='installed'").fetchone()
(f.STATE / 'ci-socket-ok').write_text('Fail2ban socket and state database accessible\n')
print('systemd sandbox: real Fail2ban socket and state database accessible', flush=True)
