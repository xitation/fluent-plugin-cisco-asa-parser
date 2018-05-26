require 'fluent/parser'

module Fluent
  class TextParser
    class FirewallParser_asa < Parser
      # Register this parser as "firewall"
      Fluent::Plugin.register_parser("cisco_asa", self)
      
      config_param :time_format, :string, default: "%b %e %H:%M:%S"

      def initialize()
        super

        @time = '\w+\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}'
        @duration = '\d{1,2}:\d{1,2}:\d{1,2}'
        @ipv6 = '((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?'
        @ipv4 = '(?<![0-9])(?:(?:[0-1]?[0-9]{1,2}|2[0-4][0-9]|25[0-5])[.](?:[0-1]?[0-9]{1,2}|2[0-4][0-9]|25[0-5])[.](?:[0-1]?[0-9]{1,2}|2[0-4][0-9]|25[0-5])[.](?:[0-1]?[0-9]{1,2}|2[0-4][0-9]|25[0-5]))(?![0-9])'
        @ip = "(?:#@ipv4|#@ipv6@)"
        @hostname = '\b(?:[0-9A-Za-z][0-9A-Za-z-]{0,62})(?:\.(?:[0-9A-Za-z][0-9A-Za-z-]{0,62}))*(\.?|\b)'
        @iporhost = "(?:#@ip|#@hostname)"
        @posint = '\b(?:[1-9][0-9]*)\b'
        @hostport = "#@iporhost:#@posint"
        @word = '\b\w+\b'
        @ext_word = '\S+'
        @data = '.*?'
        @int = '(?:[+-]?(?:[0-9]+))'
        @greedydata = '.*'
        @duration = '\d{1,2}:\d{1,2}:\d{1,2}'
        @cisco_action = '(?>Built|Teardown|Deny|Denied|denied|requested|permitted|denied by ACL|discarded|est-allowed|Dropping|created|deleted)'
        @cisco_reason = '(?>Duplicate TCP SYN|Failed to locate egress interface|Invalid transport field|No matching connection|DNS Response|DNS Query|(?:\b\w+\b\s*)*)'
        @cisco_direction = '(Inbound|inbound|Outbound|outbound)'

        # ASA-6-302013, ASA-6-302014, ASA-6-302015, ASA-6-302016
        @r1 = /^(?<time>#@time) (?<dvc_ip>#@iporhost) [^ ]* (?<action>#@cisco_action)? (?<transport>#@word) connection (?<session_id>#@int) for (?<src_zone>#@data):(?<src_ip>#@data)\/(?<src_port>#@int)( \((?<src_translated_ip>#@data)\/(?<src_translated_port>#@int)\))? to (?<dest_zone>#@data):(?<dest_ip>#@data)\/(?<dest_port>#@int)( \((?<dest_translated_ip>#@data)\/(?<dest_translated_port>#@int)\))?(?> duration (?<duration>#@duration) bytes (?<bytes>#@int))? (?>[^ ]* (?>(?<tcp_flag>#@greedydata)))?/
        # ASA-6-106015
        @r2 = /^(?<time>#@time) (?<dvc_ip>#@iporhost) [^ ]* (?<action>#@cisco_action) (?<transport>#@word) \((?<reason>#@data)\) from (?<src_ip>#@data)\/(?<src_port>#@int) to (?<dest_ip>#@data)\/(?<dest_port>#@int) flags (?<tcp_flag>\b[\w ]+\b)\s+on interface (?<dest_zone>#@ext_word)/
        # ASA-4-106023
        @r3 = /^(?<time>#@time) (?<dvc_ip>#@iporhost) [^ ]* (?<action>#@cisco_action) (?<transport>#@word) src (?<src_zone>#@data):(?<src_ip>#@data)\/(?<src_port>#@int) dst (?<dest_zone>#@data):(?<dest_ip>#@data)\/(?<dest_port>#@int) by access-group.*$/
        #ASA-2-106001
        @r4 = /^(?<time>#@time) (?<dvc_ip>#@iporhost) [^ ]* (?<direction>#@cisco_direction) (?<transport>#@word) connection (?<action>#@cisco_action) from (?<src_ip>#@data)\/(?<src_port>#@int) to (?<dest_ip>#@data)\/(?<dest_port>#@int) flags (?<tcp_flag>\b[\w ]+\b)\s+ on interface.*$/
        # ASA-3-106014
        @r5 = /^(?<time>#@time) (?<dvc_ip>#@iporhost) [^ ]* (?<action>#@cisco_action) (?<transport>icmp) src (?<src_zone>#@data):(?<src_ip>#@data) dst (?<dest_zone>#@data):(?<dest_ip>#@data) \(type (?<icmp_type>#@int), code (?<icmp_code>#@int)\)/
        # ASA-2-106006, ASA-2-106007, ASA-2-106010
        @r6 = /^(?<time>#@time) (?<dvc_ip>#@iporhost) [^ ]* (?<action>#@cisco_action) (?<direction>#@cisco_direction) (?<transport>#@data) from (?<src_ip>#@data)\/(?<src_port>#@int) to (?<dest_ip>#@data)\/(?<dest_port>#@int)\s.*$/
        # ASA-6-106100 - might need to change rule to ext_word... maybe...
        @r7 = /^(?<time>#@time) (?<dvc_ip>#@iporhost) [^ ]* access-list (?<rule>#@data) (?<action>#@cisco_action) (?<transport>#@word) (?<src_zone>#@data)\/(?<src_ip>#@data)\((?<src_port>#@int)\) -\> (?<dest_zone>#@data)\/(?<dest_ip>#@data)\((?<dest_port>#@int)\)\s.*$/
        # ASA-6-302013, ASA-6-302015
        @r8 = /^(?<time>#@time) (?<dvc_ip>#@iporhost) [^ ]* (?<action>#@cisco_action) (?<direction>#@cisco_direction) (?<transport>#@word) connection (?<session_id>#@int) for (?<src_zone>#@data):(?<src_ip>#@data)\/(?<src_port>#@int) (\((?<src_translated_ip>#@data)\/(?<src_translated_port>#@int)\))? to (?<dest_zone>#@data):(?<dest_ip>#@data)\/(?<dest_port>#@int) (\((?<dest_translated_ip>#@data)\/(?<dest_translated_port>#@int)\))?/
        # ASA-6-302014, ASA-6-302016
        @r9 = /^(?<time>#@time) (?<dvc_ip>#@iporhost) [^ ]* (?<action>#@cisco_action) (?<transport>#@word) connection (?<session_id>#@int) for (?<src_zone>#@data):(?<src_ip>#@data)\/(?<src_port>#@int) to (?<dest_zone>#@data):(?<dest_ip>#@data)\/(?<dest_port>#@int) duration (?<duration>#@duration) bytes (?<bytes>#@int)(?> [^ ]* (?<tcp_flag>#@greedydata))?/

        @asa_regex = Regexp.union(@r1, @r2, @r3, @r4, @r5, @r6, @r7, @r8, @r9)
      end

      # This method is called after config_params have read configuration parameters
      def configure(conf)
        super

        # TimeParser class is already given. It takes a single argument as the time format
        # to parse the time string with.
        @time_parser = TimeParser.new(@time_format)
      end

      # This is the main method. The input "text" is the unit of data to be parsed.
      # If this is the in_tail plugin, it would be a line. If this is for in_syslog,
      # it is a single syslog message.
      def parse(text)

        unless m = @asa_regex.match(text)
          yield nil, nil
        else
          record = {}
          time = @time_parser.parse(m['time'])

          m.names.each do |name|
            record[name] = m[name] if m[name]
          end

          yield time, record
        end
      end
    end
  end
end
