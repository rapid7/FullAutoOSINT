# FullAutoOSINT install and requirements:
# The following steps will ensure the FullAutoOSINT will run.
# It does not ensure that all of the tools are installed,
# just that all of the minimum requires for FullAutoOSINT to run are satisfied.

apt-get update
apt-get upgrade
apt-get install git python-pip

echo "At this point, run './FullAutoOSINT.py' and look for any line such as:"
echo "[!] Module ‘xxxxxxxx’ disabled. Dependency required: '['xxxxxxx']'"
echo "and make sure you install and missing tools as needed"
