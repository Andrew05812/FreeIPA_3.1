from ipaserver.plugins.user import user
from ipaserver.plugins.user import user_add, user_mod, user_show, user_find
from ipaserver.plugins.baseuser import baseuser
from ipalib import Int
from ipalib.plugable import Registry

register = Registry()

TRUSTLEVEL_OID = '1.3.6.1.4.1.53263.999.1.1'

trustlevel_param = Int(
    'trustlevel?',
    cli_name='trustlevel',
    label='Trust Level',
    doc='Numerical trust level (0-127) encoded into MS-PAC Extra SID',
    minvalue=0,
    maxvalue=127,
    attribute=True,
)

user.takes_params = user.takes_params + (trustlevel_param,)

for cmd_cls in [user_add, user_mod, user_show, user_find]:
    if hasattr(cmd_cls, 'takes_options'):
        pass

user_mod.takes_params = user_mod.takes_params + (trustlevel_param,)
user_show.takes_params = user_show.takes_params + (trustlevel_param,)
user_find.takes_params = user_find.takes_params + (trustlevel_param,)
