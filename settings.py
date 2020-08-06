#SAMPLE Settings.py where we can declare env variables

from decouple import Config, RepositoryEnv

DOTENV_FILE = 'C:\\Users\\me\.env'
env_config = Config(RepositoryEnv(DOTENV_FILE))

# use the Config().get() method as you normally would since 
# decouple.config uses that internally. 
# i.e. config('SECRET_KEY') = env_config.get('SECRET_KEY')
log_level = env_config.get('LOG_LEVEL')
dbhost = env_config.get('dbhost')
dbuser = env_config.get('dbuser')
dbpass = env_config.get('dbpass')
dbname = env_config.get('dbname')
