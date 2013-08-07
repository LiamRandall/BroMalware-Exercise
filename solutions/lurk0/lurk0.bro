##! Detects hosts involved with Bitcoin mining (or other cryptocurrencies
##! that share the same mining protocol like Litecoin, PPCoin, etc.).
##!
##! Bitcoin mining protocols typically involve the use of
##! `JSON-RPC <http://www.jsonrpc.org/specification>`_ requests to mining
##! pool servers to request work.  JSON-RPC doesn't require the use of a
##! particular transport protocol, but the original
##! `getwork <https://en.bitcoin.it/wiki/Getwork>`_ mining protocol uses
##! HTTP as a transport.  A superceding mining protocol called
##! `getblocktemplate <https://en.bitcoin.it/wiki/Getblocktemplate>`_
##! is designed to be more extensible than "getwork" by not having to rely
##! on HTTP headers to implement extensions.  Another protocol called
##! `Stratum <http://mining.bitcoin.cz/stratum-mining/>`_ is an overlay
##! network on top of the Bitcoin P2P protocol, includes methods related
##! to mining, and is not tied to a particular transport.
##!
##! This script makes use of generic JSON-RPC signatures for TCP and HTTP
##! (the most common transports used by mining software) and then inspects
##! the method values of JSON-RPC requests in order to match connections that
##! that potentially relate to Bitcoin mining.
##!
##! Note that the Bitcoin P2P protocol is not currently detected.

@load base/frameworks/notice
@load base/frameworks/signatures/main
@load base/utils/addrs
@load base/utils/directions-and-hosts

@load-sigs ./lurk0.sig

redef Signatures::ignored_ids += /lurk0/;

module Lurk0;

export {

	redef enum Notice::Type += {
		## Raised when a host doing Bitcoin mining is found.
		Lurk0_Client,

		## Raised when a host is serving work to Bitcoin miners.
		Lurk0_Server

	};

	## Type of Lurk0Host which, on discovery, should raise a notice.
	const notice_lurk0_hosts = LOCAL_HOSTS &redef;

	const notice_lurk0_hosts = LOCAL_HOSTS &redef;

	const lurk0_timeout = 60 mins &redef;
	
	global lurk0_tracker: set[addr];
}


event signature_match(state: signature_state, msg: string, data: string)
	&priority=-5
	{
	if ( /lurk0/ !in state$sig_id ) return;

	if ( state$conn$id$orig_h !in lurk0_tracker )
	{
		add lurk0_tracker[state$conn$id$orig_h];
		NOTICE([$note=Lurk0::Lurk0_Client,
		        $msg=fmt("Probable LURK0 RAT C&C Access: "),
		        $sub=data,
		        $conn=state$conn,
		        $identifier=fmt("%s%s", state$conn$id$orig_h,
		                        state$conn$id$resp_h)]);
	}
	}
