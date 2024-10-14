rubycodes= [
    r"\<\%(.*?)\%",  # <% ... %>
    r"\{\%(.*?)\}",  # %{ ... %}
    r"\<\=(.*?)\>",  # <%= ... %>
    r"\<\-.*?\-",  # <% ... -%>
    r"\.erb$",  # .erb file extension
    r"require\s+['\"]",  # require '...' or require "..."
    r"load\s+['\"]",  # load '...' or load "..."
    r"class\s+",  # class definition
    r"module\s+",  # module definition
    r"def\s+",  # method definition
    r"end\s+",  # end of block
    r"if\s+",  # if statement
    r"elsif\s+",  # elsif statement
    r"else\s+",  # else statement
    r"unless\s+",  # unless statement
    r"while\s+",  # while loop
    r"until\s+",  # until loop
    r"for\s+",  # for loop
    r"each\s+",  # each loop
    r"case\s+",  # case statement
    r"when\s+",  # when clause
    r"rescue\s+",  # rescue clause
    r"ensure\s+",  # ensure clause

    # Ruby variables and constants
    r"\@\w+",  # instance variable
    r"\@\@\w+",  # class variable
    r"\$\w+",  # global variable
    r"::\w+",  # constant

    # Ruby operators
    r"\+\+",  # increment operator
    r"--",  # decrement operator
    r"\*\*",  # exponentiation operator
    r"\/",  # division operator
    r"\%",  # modulus operator
    r"\+",  # addition operator
    r"-",  # subtraction operator
    r"\*",  # multiplication operator
    r"<",  # less than operator
    r">",  # greater than operator
    r"==",  # equality operator
    r"!=",  # inequality operator
    r"<=",  # less than or equal to operator
    r">=",  # greater than or equal to operator
    r"&&",  # logical and operator
    r"\|\|",  # logical or operator
    r"!",  # logical not operator

    # Ruby methods
    r"puts\s+",  # puts method
    r"print\s+",  # print method
    r"p\s+",  # p method
    r"gets\s+",  # gets method
    r"readline\s+",  # readline method
    r"File\.open\s+",  # File.open method
    r"File\.read\s+",  # File.read method
    r"File\.write\s+",  # File.write method
    r"Dir\.glob\s+",  # Dir.glob method
    r"Dir\.mkdir\s+",  # Dir.mkdir method
    r"Dir\.rmdir\s+",  # Dir.rmdir method

    # Ruby gems and libraries
    r"require\s+['\"]activerecord['\"]",  # ActiveRecord gem
    r"require\s+['\"]actionpack['\"]",  # ActionPack gem
    r"require\s+['\"]activesupport['\"]",  # ActiveSupport gem
    r"require\s+['\"]rails['\"]",  # Rails gem
    r"require\s+['\"]sinatra['\"]",  # Sinatra gem
    r"require\s+['\"] padrino['\"]",  # Padrino gem

    # Ruby frameworks and libraries
    r"Rails\.application",  # Rails application
    r"Sinatra\.application",  # Sinatra application
    r"Padrino\.application",  # Padrino application
    r"ActiveRecord::Base",  # ActiveRecord base class
    r"ActionController::Base",  # ActionController base class
    r"ActionView::Base",  # ActionView base class
    # Ruby blocks and closures
    r"proc\s+",  # proc block
    r"lambda\s+",  # lambda block
    r"->\s+",  # lambda arrow
    r"do\s+",  # do block
    r"end\s+",  # end of block

    # Ruby arrays and hashes
    r"\[\s+",  # array literal
    r"\{\s+",  # hash literal
    r"\[\s*.*?\s*\]",  # array with elements
    r"\{\s*.*?\s*\}",  # hash with elements

    # Ruby regular expressions
    r"/.*?/",  # regular expression literal
    r"%r{.*?}",  # regular expression literal with %r delimiter
    r"Regexp\.new\s+",  # Regexp.new method

    # Ruby exceptions and errors
    r"raise\s+",  # raise exception
    r"rescue\s+",  # rescue clause
    r"ensure\s+",  # ensure clause
    r"Exception\.new\s+",  # Exception.new method

    # Ruby threads and concurrency
    r"Thread\.new\s+",  # Thread.new method
    r"Thread\.start\s+",  # Thread.start method
    r"Thread\.join\s+",  # Thread.join method
    r"Mutex\.new\s+",  # Mutex.new method
    r"Mutex\.lock\s+",  # Mutex.lock method
    r"Mutex\.unlock\s+",  # Mutex.unlock method

    # Ruby networking and sockets
    r"Socket\.new\s+",  # Socket.new method
    r"TCPSocket\.new\s+",  # TCPSocket.new method
    r"UDPSocket\.new\s+",  # UDPSocket.new method
    r"HTTP\.new\s+",  # HTTP.new method
    r"Net::HTTP\.new\s+",  # Net::HTTP.new method

    # Ruby file and directory operations
    r"File\.exist?\s+",  # File.exist? method
    r"File\.readable?\s+",  # File.readable? method
    r"File\.writable?\s+",  # File.writable? method
    r"File\.executable?\s+",  # File.executable? method
    r"Dir\.exist?\s+",  # Dir.exist? method
    r"Dir\.mkdir\s+",  # Dir.mkdir method
    r"Dir\.rmdir\s+",  # Dir.rmdir method

    # Ruby system and process operations
    r"system\s+",  # system method
    r"exec\s+",  # exec method
    r"fork\s+",  # fork method
    r"Process\.fork\s+",  # Process.fork method
    r"Process\.wait\s+",  # Process.wait method
    r"Process\.kill\s+",  # Process.kill method
]