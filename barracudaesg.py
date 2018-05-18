from errbot import BotPlugin, botcmd, arg_botcmd, webhook
import xmlrpc.client


class Barracudaesg(BotPlugin):
    """
    API plugin for Barracuda Email Security Gateway
    """

    def activate(self):
        self.proxy = xmlrpc.client.ServerProxy("http://"+self.config.get('API_HOST')+"/cgi-mod/api.cgi?password="+self.config.get('API_PASSWORD'), verbose=True)
        super(Barracudaesg, self).activate()

    def get_configuration_template(self):
        """
        Defines the configuration structure this plugin supports
        """
        return {'API_HOST': 'host',
                'API_PASSWORD': 'password'
               }

    @webhook
    def example_webhook(self, incoming_request):
        """A webhook which simply returns 'Example'"""
        return "Example"

    # Passing split_args_with=None will cause arguments to be split on any kind
    # of whitespace, just like Python's split() does
    @botcmd(split_args_with=None)
    def whitelist(self, message, args):
        """Add domain or e-mail address to the Barracuda ESG whitelist"""
        value = self.proxy.config.create({"parent_type":"global", "name":""+args[0]+"", "type":"mta_sender_allow_address", "parent_path":"", "mta_sender_allow_comment":"errbot - "+format(message.frm)})
        yield "whitelisted {}".format(args[0])


    @botcmd(split_args_with=None)
    def blacklist(self, message, args):
        """Add domain or e-mail address to the Barracuda ESG blacklist"""
        value = self.proxy.config.create({"parent_type":"global", "name":""+args[0]+"", "type":"mta_sender_block_address", "parent_path":"", "mta_sender_block_comment":"errbot - "+format(message.frm), "mta_sender_block_action":"Block"})
        yield "blacklisted {}".format(args[0])
        
