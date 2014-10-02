#!/bin/bash
set -e


test_gem_for()
{
  version=$1

  echo "*** Installing ruby $version"
  rbenv install $version
  rbenv global $version
  gem install /tmp/kitchen/data/cryptdoh*.gem

  echo "*** Verifying install for $version"
  ruby -e 'require "cryptdoh"; Cryptdoh._verify or exit 1'
  echo "*** Done"
}

do_common()
{
  echo "*** Installing rbenc"
  git clone https://github.com/sstephenson/rbenv.git ~/.rbenv

  echo 'export PATH="$HOME/.rbenv/bin:$PATH"' >> ~/.bash_profile
  echo 'eval "$(rbenv init -)"' >> ~/.bash_profile
  source ~/.bash_profile

  echo "*** Installing ruby-build"
  git clone https://github.com/sstephenson/ruby-build.git ~/.rbenv/plugins/ruby-build

  for version in "2.1.3" "2.0.0-p576" "1.9.3-p547"; do
    test_gem_for $version
  done
}

do_debian()
{
  echo "*** Installing packages"
  apt-get install -y git libcrack2-dev
  do_common
}

do_rhel()
{
  echo "*** Installing packages"
  yum install -y git cracklib-devel
  do_common
}

release=$(cat /etc/*-release)
case "$release" in
  *Ubuntu*) do_debian;;
  *Debian*) do_debian;;
  *RHEL*) do_rhel;;
  *CentOS*) do_rhel;;
  *Amazon*) do_rhel;;
esac

