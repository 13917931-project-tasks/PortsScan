@load base/protocols/conn/removal-hooks

module portsscan;

export {
	## Log stream identifier.
	redef enum Log::ID += { LOG };

	## The ports to register portsscan for.
	const ports = {
		# TODO: Replace with actual port(s).
		22/tcp,
		22/udp,
		25/tcp,
		25/udp,
		80/tcp,
		80/udp,
		110/tcp,
		110/udp,
		143/tcp,
		143/udp,
		443/tcp,
		443/udp
		
	} &redef;

	## Record type containing the column fields of the portsscan log.
	type Info: record {
		## Timestamp for when the activity happened.
		ts: time &log;
		## Unique ID for the connection.
		uid: string &log;
		## The connection's 4-tuple of endpoint addresses/ports.
		id: conn_id &log;

		# TODO: Adapt subsequent fields as needed.

		seq_data: string &log;
		flags_data: string &log;
		window_data: string &log;
		
		## Request-side payload.
		#request: string &optional &log;
		## Response-side payload.
		#reply: string &optional &log;
	};

	## A default logging policy hook for the stream.
	global log_policy: Log::PolicyHook;

	## Default hook into portsscan logging.
	global log_portsscan: event(rec: Info);

	## portsscan finalization hook.
	global finalize_portsscan: Conn::RemovalHook;
}

redef record connection += {
	portsscan: Info &optional;
};

redef likely_server_ports += { ports };

# TODO: If you're going to send file data into the file analysis framework, you
# need to provide a file handle function. This is a simple example that's
# sufficient if the protocol only transfers a single, complete file at a time.
#
# function get_file_handle(c: connection, is_orig: bool): string
#	{
#	return cat(Analyzer::ANALYZER_PORTSSCAN, c$start_time, c$id, is_orig);
#	}

event zeek_init() &priority=5
	{
	Log::create_stream(portsscan::LOG, [$columns=Info, $ev=log_portsscan, $path="portsscan", $policy=log_policy]);

	Analyzer::register_for_ports(Analyzer::ANALYZER_PORTSSCAN, ports);

	# TODO: To activate the file handle function above, uncomment this.
	# Files::register_protocol(Analyzer::ANALYZER_PORTSSCAN, [$get_file_handle=portsscan::get_file_handle ]);
	}

# Initialize logging state.
hook set_session(c: connection)
	{
	if ( c?$portsscan )
		return;

	c$portsscan = Info($ts=network_time(), $uid=c$uid, $id=c$id);
	Conn::register_removal_hook(c, finalize_portsscan);
	}

function emit_log(c: connection)
	{
	if ( ! c?$portsscan )
		return;

	#Log::write(portsscan::LOG, c$portsscan);
	delete c$portsscan;
	}

# Example event defined in portsscan.evt.
event portsscan::message(c: connection, is_orig: bool, payload: string, seq_data: string, flags_data: string, window_data: string)
	{
	hook set_session(c);

	local info = c$portsscan;
	if ( is_orig )
		info$request = payload;
	else
		info$reply = payload;
	}
	Log::write(portsscan::LOG, [$ts=network_time(), $uid=c$uid, $id=c$id, $seq_data=seq_data, $flags_data=flags_data, $window_data=window_data]);
hook finalize_portsscan(c: connection)
	{
	# TODO: For UDP protocols, you may want to do this after every request
	# and/or reply.
	emit_log(c);
	}
