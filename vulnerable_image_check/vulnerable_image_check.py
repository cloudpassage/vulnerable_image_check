import os
from cloudpassage import HaloSession, HttpHelper
import re


class VulnerableImageCheck(object):
    """
       This class will return information for vulnerable images in monitored
       registries
    """
    def __init__(self, config):
        self.config = config
        self.integration = self.get_integration_string()

        # authenticate to get a session object
        self.session = HaloSession(
            self.config.halo_key,
            self.config.halo_secret,
            integration_string=self.integration
        )

    def vulnerable_image_check(self):
        """We use this class to scan images for vulnerabilities."""

        NONE = 0
        FAIL = "1"

        # get an HTTP helper object to call REST endpoints
        http_helper = HttpHelper(self.session)

        # get all the critical, active issues
        image_issues_endpoint = \
            "/v1/image_issues?critical=true&status=active"

        # set any query parameters set in environment
        image_issues_endpoint = \
            self.paramaterize_images_issues_endpoint(image_issues_endpoint)

        # check for vulnerabilities
        image_issues = http_helper.get(image_issues_endpoint)

        if image_issues["count"] != NONE:
            os.environ["FAIL_ON_CRITICAL"] = FAIL
        else:
            image_issues = {}

        # issue vulnerability data if exists
        return image_issues

    def paramaterize_images_issues_endpoint(self, image_issues_endpoint):
        """
        Set query parameters if in the environment.  If an environment variable
        is not set or is empty it will return everything for that variable

        Args:
            - cls - reference to the current instance of hte class
            - image_issues_endpoint (str) - the original REST endpoint

        Returns:
            - image_issues_endpoint (str) - the final endpoint
        """

        EMPTY = ""

        # if the environment has set the config registry_name set it in the
        # endpoint
        if self.config.registry_name is not None and \
                self.config.registry_name != EMPTY:
            image_issues_endpoint += \
                "&registry_name=%s" % self.config.registry_name

        # if the environment has set the config repository_name set it in the
        # endpoint
        if self.config.repository_name is not None and \
                self.config.repository_name != EMPTY:
            image_issues_endpoint += \
                "&repository_name=%s" % self.config.repository_name

        # if the environment has set the config image_tag set it in the
        # endpoint
        if self.config.image_tag is not None and \
                self.config.image_tag != EMPTY:
            image_issues_endpoint += \
                "&image_tag=%s" % self.config.image_tag

        # return the endpoint
        return image_issues_endpoint

    def get_integration_string(self):
        """Return integration string for this tool."""
        return "vulnerable_image_check/%s" % self.get_tool_version()

    def get_tool_version(self):
        """Get version of this tool from the __init__.py file."""
        here_path = os.path.abspath(os.path.dirname(__file__))
        init_file = os.path.join(here_path, "__init__.py")
        ver = 0
        with open(init_file, 'r') as i_f:
            rx_compiled = re.compile(r"\s*__version__\s*=\s*\"(\S+)\"")
            ver = rx_compiled.search(i_f.read()).group(1)
        return ver
