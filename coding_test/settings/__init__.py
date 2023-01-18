
env_name = "local"

if env_name == "prod":
    from .prod import *
else:
    from .local import *