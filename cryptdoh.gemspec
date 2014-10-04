Gem::Specification.new do |s|
  s.name        = 'cryptdoh'
  s.version     = '0.1.0'
  s.date        = '2014-10-01'
  s.summary     = "An easy to use, secure, and opinionated encryption wrapper library for Ruby."
  s.description = <<-EOF
  Most crypto libraries require the user to make significant usage decisions. Without understanding the concepts behind all the options, it is easy for the users to pick something inappropriate, resulting in insecure systems. Also, libraries often allow silly defaults, such as an IV set to all 0s or forgetting a salt etc. This library enforces best-practices, so if you need more control you should use a lower level library.
EOF
  s.authors     = ["Fraser Scott"]
  s.email       = 'fraser.scott@gmail.com'
  s.files       = ["lib/cryptdoh.rb"]
  s.homepage    = 'https://github.com/zeroXten/cryptdoh'
  s.license     = 'MIT'
  s.add_runtime_dependency "ruby-cracklib", "~> 0.1.0"
end
