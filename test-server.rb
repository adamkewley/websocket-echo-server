#!/usr/bin/env ruby

require 'open3'
require 'em-websocket-client'

Open3.popen3("bin/main") do |stdin, stdout, stderr, wait_thr|
  port = stderr.readline.match(/\d+/)

  Thread.start { sleep(0.5); exit!(0) }

  EM.run do
    conn = EventMachine::WebSocketClient.connect("ws://localhost:#{port}/")

    conn.callback do
      msg = "echoooo echhooo (should capitalize)"
      STDERR.puts "SEND: #{msg}"
      conn.send_msg msg
    end

    conn.errback do |e|
      STDERR.puts "ERR : #{e}"
    end

    conn.stream do |msg|
      STDERR.puts "RECV: #{msg}"
      if msg.data == "done"
        conn.close_connection
      end
    end

    conn.disconnect do
      STDERR.puts "DC"
      EM::stop_event_loop
    end
  end
end
