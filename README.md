Vulnerable Image Check
-

Overview
-

This project will scan all the images in registries monitored by
Halo and return a non-zero status if there are any critical vulnerabilities.  

Install
-

* pip install vulnerable_image_check - this will install the library.  
* git clone - this will allow for stand-alone usage.  

Use
-

It expects API keys to be in environment variables. 

Mandatory: 
* HALO_API_KEY - a Halo API key
* HALO_API_SECRET_KEY - a Halo API secret

Optional:
* REGISTRY_NAME - the name of a monitored registry.  If this is empty 
the output will default to all monitored registries.
* REPO_NAME - the name of a repository.  If this is empty the output will 
default to all monitored repositories.
* IMAGE_TAG - the name of an image tag.  If this is empty the output will
 default to all tags.
* OUTPUT_FORMAT - if the output format is anything other than 'csv' the output
 will be formatted text.
* OCTO_BOX - unless this is explicitly set to True, it will not run for 
octo-box.  This means the output will be decoded base64.
  
Default:
* FAIL_ON_CRITICAL = "0" - defaults to success

Stand-Alone Use:  

1) Python - python runner.py  Note: this is configured to work with both a
local or pip installed module
  
2) Docker - 

<t> * To build run:

<t><t><t>docker build -t vulnerable_image_check:latest .

<t> To execute run:

<t><t><t>docker run -it -e HALO_API_KEY=$HALO_API_KEY \
-e HALO_API_SECRET_KEY=$HALO_API_SECRET_KEY \
vulnerable_image_check

Sample Output
-

Registry: DPR    
&nbsp;&nbsp;Repository: robert_rails  
&nbsp;&nbsp;&nbsp;&nbsp;Tag: dev  
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Vulnerabilities:  Package: sensible-utils  Package Version: 0.0.9 | CVE List: cve-2017-17512 # NOQA
  Package Version: 2.0.0+dfsg-2ubuntu1.40 | CVE List: cve-2013-4544 cve-2014-0150 cve-2014-2894 # NOQA
    
Project Structure
-

* vulnerable_image_check - base directory  
1) .gitchangelog.rc - configuration file for gitchangelog  
2) .gitignore - gitignore file  
3) .travis.yml - Travis CI configuration for CI testing  
4) Dockerfile - Dockerfile for building a Docker image for running the 
application stand-alone.  There are several
 packages pinned to specific versions to remediate vulnerabilities.  
5) LICENSE - BSD 2-Clause License  
6) README.md - README.md(README_v1)  
7) setup.py - PyPI setup file    
8) runner.py  
    * vulnerable_image_check - application directory
    1) \__init\__.py - author and version string  
    2) config_helper.py - the application configuration  
    3) vulnerable_image_check.py - the application  
    <t>* lib - support scripts  
    <t>1) \__init\__.py - import and version string  
    <t>2) report.py - reporting tool that outputs base64 encoded csv and 
    formatted text  
    <t>3) utility.py - used by report.py
    * test - test directory  
    <t>* style - style tests  
    <t>1) test_style_flake8.py - flake8 tests  
    <t>* unit - unit tests  
    <t>1) test_config_helper.py - tests the application configuration  
    <t>2) test_report.py - test the report output  
    <t>3) test_vulnerable_image_check.py - test application code  


<!---
#CPTAGS:community-supported automation
#TBICON:images/python_icon.png
-->
