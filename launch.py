"""Trusted-bundle launcher; imports only the custodian's reviewed snapshot."""
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
if sys.argv[1:2]==['stage']:
    from custodian.stage import main
    raise SystemExit(main(sys.argv[2:]))
if sys.argv[1:2]==['supervise']:
    from custodian.controller import supervise
    raise SystemExit(supervise(sys.argv[2:]))
if sys.argv[1:2]==['supervise-inner']:
    del sys.argv[1]
    from pilot.supervisor import main
else:
    from pilot.gates import main
raise SystemExit(main())
