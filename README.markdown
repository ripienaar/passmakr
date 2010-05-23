What is it?
===========

A simple Ruby Library to create passwords that are pseudo random, really random (based on /dev/urandom) and phonemic.

A CLI tool is included to demonstrate the use of the library.

A simple use case for this library could be:

    require 'passmakr'
    require 'pp'

    pw = Passmakr.new(:phonemic, 8)

    pp pw.password

Output:

    {:rot13=>"trrtrrFb",
     :crypt=>"qmRSIJG2fy7Yg",
     :string=>"geegeeSo",
     :nato=>"golf echo echo golf echo echo Sierra oscar",
     :md5=>"$1$NwZQhCce$sBvOWjLEVOjSyp89HORcv/"}

This library include code from http://www.caliban.org/ruby/ruby-password.shtml for some of it's functionality.

Contact:
--------
You can contact me on rip@devco.net or follow my blog at http://www.devco.net I am also on twitter as ripienaar
