exports.Bid = function (bidid, offerer, receiver, offereditems, receiveditems, bidstatus) {
	if (null != bidid){this.bidid = bidid;}
	if (null != offerer){this.offerer = offerer;}
	if (null != receiver){this.receiver = receiver;}
	if (null != offereditems){this.offereditems = offereditems;}
	if (null != receiveditems){this.receiveditems = receiveditems;}
	if (null != bidstatus){this.bidstatus = bidstatus;}
}

exports.Item = function (id, name, description, categoryno, category, photo, date, owner) {
	if (null != id){this.item_id = id;}
	if (null != name){this.item_name = name;}
	if (null != description){this.item_desc = description;}
	if (null != categoryno){this.item_category = categoryno;}
	if (null != category){this.category_name = category;}
	if (null != photo){this.item_photo = photo;}
	if (null != date){this.item_date = date;}
	if (null != owner){this.owner = owner;}
}

exports.User = function (id, name, photo, location, locid, unreadmessagecount, lastunreadmessagedate, unreadbidcount, lastunreadbiddate, info, notificationforbids, notificationformessages) {
	if (null != id){this.u_id = id;}
	if (null != name){this.u_name = name;}
	if (null != photo){this.u_photo = photo;}
	if (null != location){this.u_location = location;}
	if (null != locid){this.c_code = locid;}
	if (null != unreadmessagecount){this.u_unreadmessages = unreadmessagecount;}
	if (null != lastunreadmessagedate){this.maxdate = lastunreadmessagedate;}
	if (null != unreadbidcount){this.u_unreadbids = unreadbidcount;}
	if (null != info){this.u_info = info;}	
	if (null != notificationforbids){this.u_notificationforbids = notificationforbids;}	
	if (null != notificationformessages){this.u_notificationformessages = notificationformessages;}	
}

exports.Message = function (messageid, senderid, receiverid, messagetext, messagetime, relateditem) {
	if (null != messageid){this.message_id = messageid;}
	if (null != senderid){this.sender_id = senderid;}
	if (null != receiverid){this.receiver_id = receiverid;}
	if (null != messagetext){this.message_text = messagetext;}
	if (null != messagetime){this.message_time = messagetime;}
	if (null != relateditem){this.related_item = relateditem;}
}