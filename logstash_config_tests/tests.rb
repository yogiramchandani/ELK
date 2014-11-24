# encoding: utf-8

require "test_utils"
require "logstash/filters/grok"

describe LogStash::Filters::Grok do
  extend LogStash::RSpec

    describe "Nominations msmq for create service" do
        config <<-CONFIG
            filter {
                grok {
                    match => { "message" => "%{TIMESTAMP_ISO8601:a_timestamp} \\[%{INT:a_thread}\\] %{WORD:a_logtype} %{GREEDYDATA:a_service} %{SYSLOG5424SD:a_processname} %{SYSLOG5424SD:a_bulkuploadid} - %{GREEDYDATA:a_message}" }
                }
                date {
                    match => [ "a_timestamp", "yyyy-MM-dd HH:mm:ss,SSS" ]
                    target => "@timestamp"
                }
          }
        CONFIG

        sample "2014-10-29 13:53:51,334 [6] INFO  App.Messaging.Processor.ProcessedMessageService [CreateService] [2109] - Saved instance 2127 at row 2." do
            insist { subject["message"]         } == "2014-10-29 13:53:51,334 [6] INFO  App.Messaging.Processor.ProcessedMessageService [CreateService] [2109] - Saved instance 2127 at row 2."
            insist { subject["tags"]            } != ["_grokparsefailure"]
            insist { subject["@timestamp"].strftime("%FT%T%:z") } == "2014-10-29T13:53:51+00:00"
            insist { subject["a_timestamp"]     } == "2014-10-29 13:53:51,334"
            insist { subject["a_thread"]        } == "6"
            insist { subject["a_logtype"]       } == "INFO"
            insist { subject["a_service"]       } == " App.Messaging.Processor.ProcessedMessageService"
            insist { subject["a_processname"]   } == "[CreateService]"
            insist { subject["a_bulkuploadid"]  } == "[2109]"
            insist { subject["a_message"]       } == "Saved instance 2127 at row 2."
        end
    end

    describe "simple syslog line" do
        # The logstash config goes here.
        # At this time, only filters are supported.
        config <<-CONFIG
          filter {
            grok {
              match => { "message" => "%{SYSLOGLINE}" }
              singles => true
              overwrite => [ "message" ]
            }
          }
        CONFIG

        sample "Mar 16 00:01:25 evita postfix/smtpd[1713]: connect from camomile.cloud9.net[168.100.1.3]" do
          insist { subject["tags"] }.nil?
          insist { subject["logsource"] } == "evita"
          insist { subject["timestamp"] } == "Mar 16 00:01:25"
          insist { subject["message"] } == "connect from camomile.cloud9.net[168.100.1.3]"
          insist { subject["program"] } == "postfix/smtpd"
          insist { subject["pid"] } == "1713"
        end
    end


end
