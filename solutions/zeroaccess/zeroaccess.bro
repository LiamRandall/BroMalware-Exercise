
@load base/frameworks/notice
@load base/frameworks/signatures/main
@load base/utils/addrs
@load base/utils/directions-and-hosts

@load-sigs ./zeroaccess.sig

redef Signatures::ignored_ids += /zeroaccess/;

module ZeroAccess;

export {

	redef enum Notice::Type += {
		## Raised when a host doing Bitcoin mining is found.
		ZeroAccess_Client,

		## Raised when a host is serving work to Bitcoin miners.
		ZeroAccess_Server

	};

	## Type of ZeroAccessHost which, on discovery, should raise a notice.
	const notice_zeroaccess_hosts = LOCAL_HOSTS &redef;

	const notice_zeroaccess_hosts = LOCAL_HOSTS &redef;

	const zeroaccess_timeout = 60 mins &redef;
	
	global zeroaccess_tracker: set[addr];
}


event signature_match(state: signature_state, msg: string, data: string)
	&priority=-5
	{
	if ( /zeroaccess/ !in state$sig_id ) return;

	if ( state$conn$id$orig_h !in zeroaccess_tracker )
	{
		add zeroaccess_tracker[state$conn$id$orig_h];
		NOTICE([$note=ZeroAccess::ZeroAccess_Client,
		        $msg=fmt("Probably ZeroAccess P2P Client Access: "),
		        $sub=data,
		        $conn=state$conn,
		        $identifier=fmt("%s%s", state$conn$id$orig_h,
		                        state$conn$id$resp_h)]);
	}
	}
