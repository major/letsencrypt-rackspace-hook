Rackspace DNS hook for letsencrypt.sh
=====================================

This repository contains a hook for the `letsencrypt.sh`_ project that allows a
user to obtain a certificate from the `Let's Encrypt`_ API via a DNS challenge
using the `dehydrated`_ client.
The hook will automatically create DNS records via the `Rackspace DNS API`_ and
remove those records when the challenge process is complete.

Have more questions?  Skip down to the FAQ section below.

.. _letsencrypt.sh: https://github.com/lukas2511/letsencrypt.sh
.. _Let's Encrypt: https://letsencrypt.org/
.. _Rackspace DNS API: https://www.rackspace.com/en-us/cloud/dns
.. _dehydrated: https://github.com/lukas2511/dehydrated

Usage
-----

Installation
~~~~~~~~~~~~

Start by cloning all of the files from GitHub:

.. code-block:: console

    $ git clone https://github.com/lukas2511/letsencrypt.sh.git
    $ cd letsencrypt.sh
    $ git clone https://github.com/major/letsencrypt-rackspace-hook.git hooks/rackspace

Install the python dependencies:

.. code-block:: console

    $ pip install -r hooks/rackspace/requirements.txt

Configuration
~~~~~~~~~~~~~

First, you will need to configure the client by creating a ``config`` 
file in the base of the letsencrypt.sh repository directory with the following:

.. code-block:: shell

    # Use the staging API until we're sure everything is working
    # (remove this later for production)
    CA="https://acme-staging.api.letsencrypt.org/directory"

Now, we export the path to our pyrax credentials file as ``PYRAX_CREDS``:

.. code-block:: shell

    export PYRAX_CREDS="/home/myuser/.pyrax"

Not familiar with `pyrax`_?  Refer to the `documentation on authentication`_ to
set up a pyrax configuration file with credentials.

Specify the domain you want to secure with an SSL certificate by creating a ``domains.txt`` in the same directory as ``config``:

.. code-block:: console

    # Single domain
    echo "example.com" > domains.txt

    # Separate multiple domains with spaces
    echo "example.com store.example.com backend.example.com" > domains.txt

Getting certificates
~~~~~~~~~~~~~~~~~~~~

We have enough configuration to obtain SSL certificates.  Let's run the main
script, specify our hook, and request a DNS challenge:

.. code-block:: console

    $ ./dehydrated --challenge dns-01 --cron --hook 'hooks/rackspace/hook.py'
    # INFO: Using main config file /home/major/git/letsencrypt.sh/config
    Processing example.com
     + Signing domains...
     + Generating private key...
     + Generating signing request...
     + Requesting challenge for example.com...
     + Rackspace hook executing: deploy_challenge
     + TXT record created: _acme-challenge.example.com => YJUYJ5DcGmQv2GsrWI4yQRZz8gIFb1pZklbRGneqON4
     + Waiting for challenge DNS record to appear on the DNS server (this usually takes 30-60 seconds)
     + Challenge record found!
     + Responding to challenge for example.com...
     + Rackspace hook executing: clean_challenge
     + Challenge is valid!
     + Requesting certificate...
     + Checking certificate...
     + Done!
     + Creating fullchain.pem...
     + Rackspace hook executing: deploy_cert
     + Certificate issued for example.com! Awesome!
     + Private key: /home/major/git/letsencrypt.sh/certs/example.com/privkey.pem
     + Certificate: /home/major/git/letsencrypt.sh/certs/example.com/cert.pem
     + Certificate w/chain: /home/major/git/letsencrypt.sh/certs/example.com/fullchain.pem
     + CA chain: /home/major/git/letsencrypt.sh/certs/example.com/chain.pem
     + Done!

Look in the ``certs`` directory to find your SSL certificates and keys!

.. _pyrax: https://github.com/rackspace/pyrax
.. _documentation on authentication: https://github.com/rackspace/pyrax/blob/master/docs/getting_started.md#set-up-authentication

FAQ
---

Can't I just buy SSL certificates like I always have?
  Absolutely!

  However, Let's Encrypt allows you to obtain certificates for
  free, which is a nice bonus.  The downside is that the certificates are only
  valid for 90 days.  If you have a mission critical system that doesn't handle
  SSL certificate updates well, you may want to purchase a longer duration
  traditional SSL certificate.

Why not use the normal HTTP challenge for Let's Encrypt?
  Some people find the HTTP challenge difficult, especially those that run many
  servers. A DNS record usually only needs to be created in one location and it
  is usually simple to add and remove.

  It can also be helpful when a website hasn't launched yet and the website is
  behind a firewall that limits HTTP access.

How do I get the certificates and keys deployed after I receive them?
  There are **plenty** of options.  I prefer to use Ansible to run
  letsencrypt.sh, pick up the files, and then copy them to remote locations.
  I also have the option to restart my web servers via Ansible once the new
  certificates are in place.

Your code sucks. What's your deal? I need this written in COBOL.
  Pull requests and issues are always welcomed on any of my repositories.

----

Enjoy! *-Major*
