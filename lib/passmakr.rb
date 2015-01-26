# Class to generate easy to remember passwords, random passwords and urandom passwords,
# it also has various utilities to crypt and hash passwords in ways compatable with various
# things like apache htpasswd, /etc/passwd, /etc/shadow and so forth
#
# It include code from http://www.caliban.org/ruby/ruby-password.shtml
class Passmakr
    attr_reader :password

    # :stopdoc:

    # This flag is used in conjunction with Passmakr.phonemic and states that a
    # password must include a digit.
    ONE_DIGIT = 1

    # This flag is used in conjunction with Passmakr.phonemic and states that a
    # password must include a capital letter.
    ONE_CASE    = 1 << 1

    # MD5 algorithm (see <em>crypt(3)</em> for more information)
    MD5 = false

    # DES algorithm
    DES = true

    # Characters that may appear in generated passwords. Passmakr.urandom may
    # also use the characters + and /.
    PASSWD_CHARS = '0123456789' +
                   'ABCDEFGHIJKLMNOPQRSTUVWXYZ' +
                   'abcdefghijklmnopqrstuvwxyz'

    # Valid salt characters for use by Passmakr#crypt.
    SALT_CHARS   = '0123456789' +
                   'ABCDEFGHIJKLMNOPQRSTUVWXYZ' +
                   'abcdefghijklmnopqrstuvwxyz' +
                   './'

    # phoneme flags
    CONSONANT = 1
    VOWEL        = 1 << 1
    DIPHTHONG = 1 << 2
    NOT_FIRST = 1 << 3  # indicates that a given phoneme may not occur first

    PHONEMES = {
        :a      => VOWEL,
        :ae     => VOWEL      | DIPHTHONG,
        :ah     => VOWEL      | DIPHTHONG,
        :ai     => VOWEL      | DIPHTHONG,
        :b      => CONSONANT,
        :c      => CONSONANT,
        :ch     => CONSONANT  | DIPHTHONG,
        :d      => CONSONANT,
        :e      => VOWEL,
        :ee     => VOWEL      | DIPHTHONG,
        :ei     => VOWEL      | DIPHTHONG,
        :f      => CONSONANT,
        :g      => CONSONANT,
        :gh     => CONSONANT  | DIPHTHONG | NOT_FIRST,
        :h      => CONSONANT,
        :i      => VOWEL,
        :ie     => VOWEL      | DIPHTHONG,
        :j      => CONSONANT,
        :k      => CONSONANT,
        :l      => CONSONANT,
        :m      => CONSONANT,
        :n      => CONSONANT,
        :ng     => CONSONANT  | DIPHTHONG | NOT_FIRST,
        :o      => VOWEL,
        :oh     => VOWEL      | DIPHTHONG,
        :oo     => VOWEL      | DIPHTHONG,
        :p      => CONSONANT,
        :ph     => CONSONANT  | DIPHTHONG,
        :qu     => CONSONANT  | DIPHTHONG,
        :r      => CONSONANT,
        :s      => CONSONANT,
        :sh     => CONSONANT  | DIPHTHONG,
        :t      => CONSONANT,
        :th     => CONSONANT  | DIPHTHONG,
        :u      => VOWEL,
        :v      => CONSONANT,
        :w      => CONSONANT,
        :x      => CONSONANT,
        :y      => CONSONANT,
        :z      => CONSONANT
    }

    # :startdoc:

    # Creates a password instance, possible modes are:
    #
    # * :phonemic - produces easily remembered passwords
    # * :random - uses the ruby random function to generate a password
    # * :urandom - uses linux /dev/urandom to generate a password
    # * anything else will be used as the password instead of generating one
    #
    # Each instance will have a unique hash of password information
    # in the password attribute, the hash will have members:
    #
    # * :string - the actual password string
    # * :crypt - a crypt encoded version with a salt, usable in unix password hashes
    # * :md5 - a md5 hash usable in unix password hashes
    # * :nato - a NATO alphabet readable version of the password
    # * :rot13 - for kicks, a ro13 encoded version of the password
    def initialize(mode=:phonemic, length=8)
        pw = nil

        case mode
            when :urandom
                pw = urandom(length)
            when :random
                pw = random(length)
            when :phonemic
                pw = phonemic(length)
            else
                pw = mode
        end

        preppw(pw)
    end

    private
    # Determine whether next character should be a vowel or consonant.
    def get_vowel_or_consonant
        rand( 2 ) == 1 ? VOWEL : CONSONANT
    end

    # Generate a memorable password of _length_ characters, using phonemes that
    # a human-being can easily remember. _flags_ is one or more of
    # <em>Passmakr::ONE_DIGIT</em> and <em>Passmakr::ONE_CASE</em>, logically
    # OR'ed together. For example:
    #
    #  pw = Passmakr.phonemic( 8, Passmakr::ONE_DIGIT | Passmakr::ONE_CASE )
    #
    # This would generate an eight character password, containing a digit and an
    # upper-case letter, such as <b>Ug2shoth</b>.
    #
    # This method was inspired by the
    # pwgen[http://sourceforge.net/projects/pwgen/] tool, written by Theodore
    # Ts'o.
    #
    # Generated passwords may contain any of the characters in
    # <em>Passmakr::PASSWD_CHARS</em>.
    def phonemic(length=8, flags=Passmakr::ONE_CASE)

        pw = nil
        ph_flags = flags

        loop do

            pw = ""

            # Separate the flags integer into an array of individual flags
            feature_flags = [ flags & ONE_DIGIT, flags & ONE_CASE ]

            prev = []
            first = true
            desired = get_vowel_or_consonant

            # Get an Array of all of the phonemes
            phonemes = PHONEMES.keys.map { |ph| ph.to_s }
            nr_phonemes = phonemes.size

            while pw.length < length do

                # Get a random phoneme and its length
                phoneme = phonemes[ rand( nr_phonemes ) ]
                ph_len = phoneme.length

                # Get its flags as an Array
                ph_flags = PHONEMES[ phoneme.to_sym ]
                ph_flags = [ ph_flags & CONSONANT, ph_flags & VOWEL,
                    ph_flags & DIPHTHONG, ph_flags & NOT_FIRST ]

                # Filter on the basic type of the next phoneme
                next if ph_flags.include? desired

                # Handle the NOT_FIRST flag
                next if first and ph_flags.include? NOT_FIRST

                # Don't allow a VOWEL followed a vowel/diphthong pair
                next if prev.include? VOWEL and ph_flags.include? VOWEL and
                    ph_flags.include? DIPHTHONG

                # Don't allow us to go longer than the desired length
                next if ph_len > length - pw.length

                # We've found a phoneme that meets our criteria
                pw << phoneme

                # Handle ONE_CASE
                if feature_flags.include? ONE_CASE

                    if (first or ph_flags.include? CONSONANT) and rand( 10 ) < 3
                        pw[-ph_len, 1] = pw[-ph_len, 1].upcase
                        feature_flags.delete ONE_CASE
                    end

                end

                # Is password already long enough?
                break if pw.length >= length

                # Handle ONE_DIGIT
                if feature_flags.include? ONE_DIGIT

                    if ! first and rand( 10 ) < 3
                        pw << ( rand( 10 ) + ?0 ).chr
                        feature_flags.delete ONE_DIGIT

                        first = true
                        prev = []
                        desired = get_vowel_or_consonant
                        next
                    end

                end

                if desired == CONSONANT
                    desired = VOWEL
                elsif prev.include? VOWEL or ph_flags.include? DIPHTHONG or
                    rand(10) > 3
                    desired = CONSONANT
                else
                    desired = VOWEL
                end

                prev = ph_flags
                first = false
            end

            # Try again
            break unless feature_flags.include? ONE_CASE or feature_flags.include? ONE_DIGIT

        end

        pw
    end


    # Generate a random password of _length_ characters. Unlike the
    # Passmakr.phonemic method, no attempt will be made to generate a memorable
    # password. Generated passwords may contain any of the characters in
    # <em>Passmakr::PASSWD_CHARS</em>.
    def random(length=8)
        pw = ""
        nr_chars = PASSWD_CHARS.size

        srand()

        length.times { pw << PASSWD_CHARS[ rand( nr_chars ) ] }

        pw
    end


    # An alternative to Passmakr.random. It uses the <tt>/dev/urandom</tt>
    # device to generate passwords, returning +nil+ on systems that do not
    # implement the device. The passwords it generates may contain any of the
    # characters in <em>Passmakr::PASSWD_CHARS</em>, plus the additional
    # characters + and /.
    def urandom(length=8)
        return nil unless File.chardev? '/dev/urandom'

        rand_data = nil
        File.open( "/dev/urandom" ) { |f| rand_data = f.read( length ) }

        # Base64 encode it
        pw = [ rand_data ].pack( 'm' )[ 0 .. length - 1 ]
    end

    # Encrypt a password using _type_ encryption. _salt_, if supplied, will be
    # used to perturb the encryption algorithm and should be chosen from the
    # <em>Passmakr::SALT_CHARS</em>. If no salt is given, a randomly generated
    # salt will be used.
    def crypt(pw, type=DES, salt='')

        unless ( salt.split( // ) - SALT_CHARS.split( // ) ).empty?
            raise CryptError, 'bad salt'
        end

        salt = random( type ? 2 : 8 ) if salt.empty?

        # (Linux glibc2 interprets a salt prefix of '$1$' as a call to use MD5
        # instead of DES when calling crypt(3))
        salt = '$1$' + salt if type == MD5

        crypt = pw.crypt(salt)

        # Raise an exception if MD5 was wanted, but result is not recognisable
        if type == MD5 && crypt !~ /^\$1\$/
            raise CryptError, 'MD5 not implemented'
        end

        crypt
    end

    # prepares @password using the password passed as a string
    def preppw(pw)
        rot13 = pw.tr("A-Za-z", "N-ZA-Mn-za-m")

        @password = {:string => pw, :nato => pw.to_nato,
                     :crypt => crypt(pw), :md5 => crypt(pw, MD5),
                     :rot13 => rot13 }
    end
end

class String
    NATOALPHA = ["alfa", "bravo", "charlie", "delta", "echo", "foxtrot", "golf", "hotel",
                 "india", "juliet", "kilo", "lima", "mike", "november", "oscar", "papa",
                 "quebec", "romeo", "sierra", "tango", "uniform", "victor", "whiskey",
                 "xray", "yankee", "zulu"]

    NATODIGITS = ["zero", "one", "two", "three", "four", "five", "six", "seven", "eight", "nine"]

    # Returns a NATO alphabet version of the string
    def to_nato
        result = nil

        # for strings we call ourself recursively for each char to build up the eventual string
        if self.size > 1
            result = self.split("").map {|c| c.to_nato }.join(" ")
        else
            ansi = self.bytes.first

            if ansi >= 65 && ansi <= 90
                result = NATOALPHA[ansi-65].capitalize
            elsif ansi >= 97 && ansi <= 122
                result = NATOALPHA[ansi-97]
            elsif ansi >= 48 && ansi <= 57
                result = NATODIGITS[ansi-48]
            else
                result = self
            end
        end

        result
    end
end

# vim:tabstop=4:expandtab:ai
