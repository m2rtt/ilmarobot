/*
 * Copyright 2016-present, Facebook, Inc.
 * All rights reserved.
 *
 * This source code is licensed under the license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

/* jshint node: true, devel: true */
'use strict';
const 
  bodyParser = require('body-parser'),
  config = require('config'),
  crypto = require('crypto'),
  express = require('express'),
  https = require('https'),
  request = require('request');

var app = express();
app.set('port', process.env.PORT || 5000);
app.set('view engine', 'ejs');
app.use(bodyParser.json({ verify: verifyRequestSignature }));
app.use(express.static('public'));

var dict = {};
/*
 * Be sure to setup your config values before running this code. You can 
 * set them using environment variables or modifying the config file in /config.
 *
 */

// App Secret can be retrieved from the App Dashboard
const APP_SECRET = (process.env.MESSENGER_APP_SECRET) ? 
  process.env.MESSENGER_APP_SECRET :
  config.get('appSecret');

// Arbitrary value used to validate a webhook
const VALIDATION_TOKEN = (process.env.MESSENGER_VALIDATION_TOKEN) ?
  (process.env.MESSENGER_VALIDATION_TOKEN) :
  config.get('validationToken');

// Generate a page access token for your page from the App Dashboard
const PAGE_ACCESS_TOKEN = (process.env.MESSENGER_PAGE_ACCESS_TOKEN) ?
  (process.env.MESSENGER_PAGE_ACCESS_TOKEN) :
  config.get('pageAccessToken');

// URL where the app is running (include protocol). Used to point to scripts and 
// assets located at this address. 
const SERVER_URL = (process.env.SERVER_URL) ?
  (process.env.SERVER_URL) :
  config.get('serverURL');

if (!(APP_SECRET && VALIDATION_TOKEN && PAGE_ACCESS_TOKEN && SERVER_URL)) {
  console.error("Missing config values");
  process.exit(1);
}

/*
 * Use your own validation token. Check that the token used in the Webhook 
 * setup is the same token used here.
 *
 */
app.get('/webhook', function(req, res) {
  if (req.query['hub.mode'] === 'subscribe' &&
      req.query['hub.verify_token'] === VALIDATION_TOKEN) {
    console.log("Validating webhook");
    res.status(200).send(req.query['hub.challenge']);
  } else {
    console.error("Failed validation. Make sure the validation tokens match.");
    res.sendStatus(403);          
  }  
});


/*
 * All callbacks for Messenger are POST-ed. They will be sent to the same
 * webhook. Be sure to subscribe your app to your page to receive callbacks
 * for your page. 
 * https://developers.facebook.com/docs/messenger-platform/product-overview/setup#subscribe_app
 *
 */
app.post('/webhook', function (req, res) {
  var data = req.body;

  // Make sure this is a page subscription
  if (data.object == 'page') {
    // Iterate over each entry
    // There may be multiple if batched
    data.entry.forEach(function(pageEntry) {
      var pageID = pageEntry.id;
      var timeOfEvent = pageEntry.time;

      // Iterate over each messaging event
      pageEntry.messaging.forEach(function(messagingEvent) {
        if (messagingEvent.optin) {
          receivedAuthentication(messagingEvent);
        } else if (messagingEvent.message) {
          receivedMessage(messagingEvent);
        } else if (messagingEvent.delivery) {
          receivedDeliveryConfirmation(messagingEvent);
        } else if (messagingEvent.postback) {
          receivedPostback(messagingEvent);
        } else if (messagingEvent.read) {
          receivedMessageRead(messagingEvent);
        } else if (messagingEvent.account_linking) {
          receivedAccountLink(messagingEvent);
        } else {
          console.log("Webhook received unknown messagingEvent: ", messagingEvent);
        }
      });
    });

    // Assume all went well.
    //
    // You must send back a 200, within 20 seconds, to let us know you've 
    // successfully received the callback. Otherwise, the request will time out.
    res.sendStatus(200);
  }
});

/*
 * This path is used for account linking. The account linking call-to-action
 * (sendAccountLinking) is pointed to this URL. 
 * 
 */
app.get('/authorize', function(req, res) {
  var accountLinkingToken = req.query.account_linking_token;
  var redirectURI = req.query.redirect_uri;

  // Authorization Code should be generated per user by the developer. This will 
  // be passed to the Account Linking callback.
  var authCode = "1234567890";

  // Redirect users to this URI on successful login
  var redirectURISuccess = redirectURI + "&authorization_code=" + authCode;

  res.render('authorize', {
    accountLinkingToken: accountLinkingToken,
    redirectURI: redirectURI,
    redirectURISuccess: redirectURISuccess
  });
});

/*
 * Verify that the callback came from Facebook. Using the App Secret from 
 * the App Dashboard, we can verify the signature that is sent with each 
 * callback in the x-hub-signature field, located in the header.
 *
 * https://developers.facebook.com/docs/graph-api/webhooks#setup
 *
 */
function verifyRequestSignature(req, res, buf) {
  var signature = req.headers["x-hub-signature"];

  if (!signature) {
    // For testing, let's log an error. In production, you should throw an 
    // error.
    console.error("Couldn't validate the signature.");
  } else {
    var elements = signature.split('=');
    var method = elements[0];
    var signatureHash = elements[1];

    var expectedHash = crypto.createHmac('sha1', APP_SECRET)
                        .update(buf)
                        .digest('hex');

    if (signatureHash != expectedHash) {
      throw new Error("Couldn't validate the request signature.");
    }
  }
}

/*
 * Authorization Event
 *
 * The value for 'optin.ref' is defined in the entry point. For the "Send to 
 * Messenger" plugin, it is the 'data-ref' field. Read more at 
 * https://developers.facebook.com/docs/messenger-platform/webhook-reference/authentication
 *
 */
function receivedAuthentication(event) {
  var senderID = event.sender.id;
  var recipientID = event.recipient.id;
  var timeOfAuth = event.timestamp;

  // The 'ref' field is set in the 'Send to Messenger' plugin, in the 'data-ref'
  // The developer can set this to an arbitrary value to associate the 
  // authentication callback with the 'Send to Messenger' click event. This is
  // a way to do account linking when the user clicks the 'Send to Messenger' 
  // plugin.
  var passThroughParam = event.optin.ref;

  console.log("Received authentication for user %d and page %d with pass " +
    "through param '%s' at %d", senderID, recipientID, passThroughParam, 
    timeOfAuth);

  // When an authentication is received, we'll send a message back to the sender
  // to let them know it was successful.
  sendTextMessage(senderID, "Authentication successful");
}

/*
 * Message Event
 *
 * This event is called when a message is sent to your page. The 'message' 
 * object format can vary depending on the kind of message that was received.
 * Read more at https://developers.facebook.com/docs/messenger-platform/webhook-reference/message-received
 *
 * For this example, we're going to echo any text that we get. If we get some 
 * special keywords ('button', 'generic', 'receipt'), then we'll send back
 * examples of those bubbles to illustrate the special message bubbles we've 
 * created. If we receive a message with an attachment (image, video, audio), 
 * then we'll simply confirm that we've received the attachment.
 * 
 */
function receivedMessage(event) {
  var senderID = event.sender.id;
  var recipientID = event.recipient.id;
  var timeOfMessage = event.timestamp;
  var message = event.message;
  if (dict[senderID] == undefined) {
    dict[senderID] = {'aeg':'hetkel'};
  }
  console.log("Received message for user %d and page %d at %d with message:", 
    senderID, recipientID, timeOfMessage);
  console.log(JSON.stringify(message));

  var isEcho = message.is_echo;
  var messageId = message.mid;
  var appId = message.app_id;
  var metadata = message.metadata;

  // You may get a text or attachment but not both
  var messageText = message.text;
  var messageAttachments = message.attachments;
  var quickReply = message.quick_reply;

  if (isEcho) {
    // Just logging message echoes to console
    console.log("Received echo for message %s and app %d with metadata %s", 
      messageId, appId, metadata);
    return;
  } else if (quickReply) {
    var quickReplyPayload = quickReply.payload;
    console.log("Quick reply for message %s with payload %s",
      messageId, quickReplyPayload);

    sendTextMessage(senderID, "Quick reply tapped");
    return;
  }
  var response = "Huh?";
  var check = false;
  if (messageText) {
    if (messageText.match(/[tT]ere|[Hh]ei|[Tt]sau|[Tt]erv/))
      sendTextMessage(senderID, "Tere!" );

    if(dict[senderID]['linn'] != undefined && !messageText.match(/[Ll]inn\w*/))
      kontrollLaused(messageText, senderID);
    if (messageText.match(/[Ll]inn\w*/)) {
      var str = messageText.match(/[Ll]inn\w*/);
      var linn = messageText.substring(str.index + str[0].length).match(/[A-ZÕÄÖÜ][a-zõäöü]+((( |-)[A-ZÕÄÖÜa-zõäöü][a-zõäöü]+)*( |-)[A-ZÕÄÖÜ][a-zõäöü]+)?/)[0];
      dict[senderID]['linn'] = linn;
      //getIlmJSON(encodeURIComponent(linn), senderID);
      getIlmJSON(encodeURIComponent(linn), senderID, function(cb) {
        dict[senderID]['ilm'] = cb;
        if(!cb)
          sendTextMessage(senderID, "ilmnes probleem");
        else
          kontrollLaused(messageText, senderID);
      });
    }
    if (check)
      sendTextMessage(senderID, response);

    // If we receive a text message, check to see if it matches any special
    // keywords and send back the corresponding example. Otherwise, just echo
    // the text we received.
    switch (messageText) {
      case 'image':
        sendImageMessage(senderID);
        break;

      case 'button':
        sendButtonMessage(senderID);
        break;

      case 'generic':
        sendGenericMessage(senderID);
        break;

      case 'receipt':
        sendReceiptMessage(senderID);
        break;

      case 'quick reply':
        sendQuickReply(senderID);
        break;        

      case 'read receipt':
        sendReadReceipt(senderID);
        break;        

      case 'typing on':
        sendTypingOn(senderID);
        break;        

      case 'typing off':
        sendTypingOff(senderID);
        break;        

      case 'account linking':
        sendAccountLinking(senderID);
        break;

      default:
        sendTypingOff(senderID);
    }
  } else if (messageAttachments) {
    sendTypingOff(senderID);
  }
}
function kontrollLaused(messageText, senderID) {
  var response = 'Ma ei saa teist aru'; 
  var check = false;
      if (messageText.match(/ilm/)) {
      dict[senderID]['viimane'] = 'ilm';
      if (dict[senderID]['linn'] == undefined)
        response = "Täpsustage linna nimi.";
      else
        response = getIlmText(dict[senderID]['linn'], dict[senderID]['ilm'], dict[senderID]['aeg'])
    }
    if (messageText.match(/(õhu)?niiskus/)) {
      dict[senderID]['viimane'] = 'õhuniiskus';
      if (dict[senderID]['linn'] == undefined)
        response = "Täpsustage linna nimi.";
      else
        response = getÕhuniiskusText(dict[senderID]['linn'],
                    dict[senderID]['ilm']['list'][getAegIndex(dict[senderID]['ilm'], dict[senderID]['aeg'])]['main']['humidity'],
                    dict[senderID]['aeg']);    
    }
    if (messageText.match(/temperatuur|kraad|sooja|külm|soe/)) {
      dict[senderID]['viimane'] = 'temperatuur';
      if (dict[senderID]['linn'] == undefined)
        response = "Täpsustage linna nimi.";
      else
        response = getTemperatuurText(dict[senderID]['linn'],
                    dict[senderID]['ilm']['list'][getAegIndex(dict[senderID]['ilm'], dict[senderID]['aeg'])]['main']['temp'],
                    dict[senderID]['aeg']);        
    }
    if (messageText.match(/(õhu)?rõhk/)) {
      dict[senderID]['viimane'] = 'õhurõhk';
      if (dict[senderID]['linn'] == undefined)
        response = "Täpsustage linna nimi.";
      else
        response = getÕhurõhkText(dict[senderID]['linn'],
                    dict[senderID]['ilm']['list'][getAegIndex(dict[senderID]['ilm'], dict[senderID]['aeg'])]['main']['pressure'],
                    dict[senderID]['aeg']);    
    }
    if (messageText.match(/tuul/)) {
      dict[senderID]['viimane'] = 'tuul';
      if (messageText.match(/suun.*/)) {
        dict[senderID]['viimane'] = 'tuulesuund';
        if (messageText.match(/kiirus|kiire/))
          dict[senderID]['viimane'] = 'tuul';
      }
      if (messageText.match(/kiirus|kiire/) && !messageText.match(/suun/))
        dict[senderID]['viimane'] = 'tuulekiirus';
      if (dict[senderID]['linn'] == undefined)
        response = "Täpsustage linna nimi."
      else
        response = getTuulText(dict[senderID]['linn'], dict[senderID]['ilm'], dict[senderID]['viimane'], dict[senderID]['aeg'], senderID)
    }
    if (messageText.match(/täna|hetkel|praegu|nüüd/)) {
      dict[senderID]['aeg'] = 'hetkel';
      if (dict[senderID]['linn'] != undefined && dict[senderID]['ilm'] != undefined){
        response = getYldineIlm(dict[senderID]['ilm'], dict[senderID]['linn'], dict[senderID]['aeg'], senderID);
      }
    }
    if (messageText.match(/õhtu|öö/)) {
      dict[senderID]['aeg'] = 'õhtu';
      if (dict[senderID]['linn'] != undefined && dict[senderID]['ilm'] != undefined){
        response = getYldineIlm(dict[senderID]['ilm'], dict[senderID]['linn'], dict[senderID]['aeg'], senderID);
      }
    }
    if (messageText.match(/lõuna|päev/)) {
      dict[senderID]['aeg'] = 'päev';
      if (dict[senderID]['linn'] != undefined && dict[senderID]['ilm'] != undefined){
        response = getYldineIlm(dict[senderID]['ilm'], dict[senderID]['linn'], dict[senderID]['aeg'], senderID);
      }
    }
    if (messageText.match(/homme|homne/)) {
      dict[senderID]['aeg'] = 'hommepäev';
      if (messageText.match(/hommik/))
        dict[senderID]['aeg'] = 'hommehommik';
      if (messageText.match(/õhtu|öö/))
        dict[senderID]['aeg'] = 'hommeõhtu';
      if (dict[senderID]['linn'] != undefined && dict[senderID]['ilm'] != undefined){
        response = getYldineIlm(dict[senderID]['ilm'], dict[senderID]['linn'], dict[senderID]['aeg'], senderID);
      }
    }
    if (messageText.match(/üle(homme|homne)/)) {
      dict[senderID]['aeg'] = 'ülehommepäev';
      if (messageText.match(/hommik/))
        dict[senderID]['aeg'] = 'ülehommehommik';
      if (messageText.match(/õhtu|öö/))
        dict[senderID]['aeg'] = 'ülehommeõhtu';
      if (dict[senderID]['linn'] != undefined && dict[senderID]['ilm'] != undefined){
        response = getYldineIlm(dict[senderID]['ilm'], dict[senderID]['linn'], dict[senderID]['aeg'], senderID);
        check = true;
      }
    }
    //if (response == 'Ma ei saa teist aru')
    //  response = getYldineIlm(dict[senderID]['ilm'], dict[senderID]['linn'], dict[senderID]['aeg'], senderID);
    sendTextMessage(senderID, response);
}
function getYldineIlm(ilm, linn, aeg, uid) {
  var i = getAegIndex(ilm, aeg);
  var res = '';
  if (dict[uid]['viimane'] == 'õhuniiskus')
    res = getÕhuniiskusText(linn, ilm['list'][i]['main']['humidity'], aeg);
  if (dict[uid]['viimane'] == 'temperatuur')
    res = getTemperatuurText(linn, ilm['list'][i]['main']['temp'], aeg);
  if (dict[uid]['viimane'] == 'õhurõhk')
    res = getÕhurõhkText(linn, ilm['list'][i]['main']['pressure'], aeg);
  if (dict[uid]['viimane'].indexOf('tuul') != -1)
    res = getTuulText(linn, ilm, dict[uid]['viimane'], aeg, uid);
  if (dict[uid]['viimane'] == 'ilm')
    res = getIlmText(linn, ilm, aeg);
  return res;
}
function getIlmText(linn, ilm, aeg) {
  var i = getAegIndex(ilm, aeg);
  var temp = ilm['list'][i]['main']['temp'];
  var kiirus = ilm['list'][i]['wind']['speed'];
  var tuulesuund = ilm['list'][i]['wind']['deg'];
  var pressure = ilm['list'][i]['main']['pressure'];
  var niiskus = ilm['list'][i]['main']['humidity'];
  var t = "";
  if (getIlmKirjeldus(ilm, i) == "")
    t == " ";
  else
    t = " " + getIlmKirjeldus(ilm, i) + ", "
  return getAegText(aeg) + " linnas " + linn + t + "temperatuur on " + temp + " kraadi, puhub tuul " + getTuulesuund(tuulesuund) + " " + kiirus + " m/s, õhurõhk on " + pressure + " hPa ja õhuniiskus " + niiskus + "%";  
}
function getÕhuniiskusText(linn, niiskus, aeg) {
  return "Linnas " + linn + " on " + getAegText(aeg).toLowerCase() + " õhuniiskust " + niiskus + "%";
}

function getTemperatuurText(linn, temp, aeg) {
  return "Linnas " + linn + " on " + getAegText(aeg).toLowerCase() + " temperatuur " + temp + " kraadi";
}
    
function getÕhurõhkText(linn, pressure, aeg) {
  return "Linnas " + linn + " on " + getAegText(aeg).toLowerCase() + " õhurõhk " + pressure + " hPa";
}

function getTuulText(linn, ilm, viimane, aeg, uid){
  var response = "";
  var tuulesuund = ilm['list'][getAegIndex(ilm, aeg)]['wind']['deg'];
  var kiirus = ilm['list'][getAegIndex(ilm, aeg)]['wind']['speed'];    
  var t = getTuulesuund(tuulesuund);
  if (dict[uid]['viimane'] == "tuulesuund")
    response = "Linnas " + linn + " puhub " + getAegText(aeg) + " tuul " + t;
  else if (dict[uid]['viimane'] == "tuul")
    response = "Linnas " + linn + " puhub " + getAegText(aeg) + " tuul " + t + " " + kiirus + " m/s";
  else if (dict[uid]['viimane'] == "tuulekiirus")
    response = "Linnas " + linn + " on " + getAegText(aeg) + " tuulekiirus " + kiirus + " m/s";
  return response;
}
function getTuulesuund(deg) {
  var t = "";
    if (deg >= 337.5 && deg <= 360.0 || deg < 22.5 && deg >= 0.0)
      t = "põhjast";
    else if (deg >= 22.5 && deg < 67.5)
      t = "kirdest";
    else if (deg >= 67.5 && deg < 112.5)
      t = "idast";
    else if (deg >= 112.5 && deg < 157.5)
      t = "kagust";
    else if (deg >= 157.5 && deg < 202.5)
      t = "lõunast";
    else if (deg >= 202.5 && deg < 247.5)
      t = "edelast";
    else if (deg >= 247.5 && deg < 292.5)
      t = "läänest";
    else if (deg >= 292.5 && deg < 337.5)
      t = "loodest";
    return t;
  }
function getIlmKirjeldus(ilm, index) {
  var desc = ilm['list'][index]['weather'][0]['main']
    if (desc == "Thunderstorm")
        return "on äike";
    if (desc == "Drizzle")
        return "sajab uduvihma";
    if (desc == "Rain")
        return "sajab vihma";
    if (desc == "Snow")
        return "sajab lund";
    if (desc == "Clouds")
        return "on pilves";
    if (desc == "Clear")
        return "on selge ilm";
    if (desc == "Extreme")
        return "on ekstreemsed olud";
    if (desc == "Atmosphere")
        return "on udu"; //see ei ole kindlasti alati correct
    else
        return "";
}
function getAegText(aeg) {
  var at = ""
  var date = new Date();
  if (aeg == "hetkel")
    at = "Hetkel";
  else if (aeg == "päev")
    at = "Täna päeval";
    if (date.getHours() >= 15)
      at = "Hetkel";
  else if (aeg == "õhtu")
    at = "Täna õhtul";
    if (date.getHours() >= 21)
      at = "Hetkel";
  else if (aeg == "hommehommik")
    at = "Homme hommikul";
  else if (aeg == "hommepäev")
    at = "Homme päeval";
  else if (aeg == "hommeõhtu")
    at = "Homme õhtul";
  else if (aeg == "ülehommehommik")
    at = "Ülehomme hommikul";
  else if (aeg == "ülehommepäev")
    at = "Ülehomme päeval";
  else if (aeg == "ülehommeõhtu")
    at = "Ülehomme õhtul";
  return at;
}
function getAegIndex(ilm, aeg) {
  if (aeg == 'hetkel')
    return 0;
  var date = new Date();
  for (var i = 0; i < ilm['list'].length; i++) {
    var kp = ilm['list'][i]['dt_txt'].split(" ")[0];
    var p = parseInt(kp.split("-")[2]);
    var kell = ilm['list'][i]['dt_txt'].split(" ")[1];
    var k = parseInt(kell.split(":")[0])
    if (aeg == "päev") {
      if (p == date.getDate()) {
        if (k == 15)
          return i
      }
    } else if (aeg == "õhtu"){
      if (p == date.getDate()) {
        if (k == 21)
          return i
      }      
    } else if (aeg == "hommehommik"){
      if (p == date.getDate()+1) {
        if (k == 9)
          return i
      }      
    } else if (aeg == "hommepäev"){
      if (p == date.getDate()+1) {
        if (k == 15)
          return i
      }      
    } else if (aeg == "hommeõhtu"){
      if (p == date.getDate()+1) {
        if (k == 21)
          return i
      }      
    } else if (aeg == "ülehommehommik"){
      if (p == date.getDate()+2) {
        if (k == 9)
          return i
      }      
    } else if (aeg == "ülehommepäev"){
      if (p == date.getDate()+2) {
        if (k == 15)
          return i
      }      
    } else if (aeg == "ülehommeõhtu"){
      if (p == date.getDate()+2) {
        if (k == 21)
          return i
      }      
    }
  }
  return 0;
}
function getIlmJSON(linn, uid, callback){
        var apiKey = 'da4e1bd6fbe3a91e49486215b059c31a';
        sendTypingOn(uid);
        request('http://api.openweathermap.org/data/2.5/forecast/city?APPID='+ apiKey +'&q='+ linn +'&units=metric', getIlm);
        function getIlm(err, response, body){
          if(!err && response.statusCode < 400){
            var retData = JSON.parse(body);
            //console.log(retData);
            dict[uid]['ilm'] = retData;
            if (!retData)
              sendTextMessage(uid, "Probleem");
            else
              callback(retData);
            sendTypingOff(uid);
          }
          else{
            console.log(err);
            console.log(response.statusCode);
          }
        }
      };
/*
 * Delivery Confirmation Event
 *
 * This event is sent to confirm the delivery of a message. Read more about 
 * these fields at https://developers.facebook.com/docs/messenger-platform/webhook-reference/message-delivered
 *
 */
function receivedDeliveryConfirmation(event) {
  var senderID = event.sender.id;
  var recipientID = event.recipient.id;
  var delivery = event.delivery;
  var messageIDs = delivery.mids;
  var watermark = delivery.watermark;
  var sequenceNumber = delivery.seq;

  if (messageIDs) {
    messageIDs.forEach(function(messageID) {
      console.log("Received delivery confirmation for message ID: %s", 
        messageID);
    });
  }

  console.log("All message before %d were delivered.", watermark);
}


/*
 * Postback Event
 *
 * This event is called when a postback is tapped on a Structured Message. 
 * https://developers.facebook.com/docs/messenger-platform/webhook-reference/postback-received
 * 
 */
function receivedPostback(event) {
  var senderID = event.sender.id;
  var recipientID = event.recipient.id;
  var timeOfPostback = event.timestamp;

  // The 'payload' param is a developer-defined field which is set in a postback 
  // button for Structured Messages. 
  var payload = event.postback.payload;

  console.log("Received postback for user %d and page %d with payload '%s' " + 
    "at %d", senderID, recipientID, payload, timeOfPostback);

  // When a postback is called, we'll send a message back to the sender to 
  // let them know it was successful
  sendTextMessage(senderID, "Postback called");
}

/*
 * Message Read Event
 *
 * This event is called when a previously-sent message has been read.
 * https://developers.facebook.com/docs/messenger-platform/webhook-reference/message-read
 * 
 */
function receivedMessageRead(event) {
  var senderID = event.sender.id;
  var recipientID = event.recipient.id;

  // All messages before watermark (a timestamp) or sequence have been seen.
  var watermark = event.read.watermark;
  var sequenceNumber = event.read.seq;

  console.log("Received message read event for watermark %d and sequence " +
    "number %d", watermark, sequenceNumber);
}

/*
 * Account Link Event
 *
 * This event is called when the Link Account or UnLink Account action has been
 * tapped.
 * https://developers.facebook.com/docs/messenger-platform/webhook-reference/account-linking
 * 
 */
function receivedAccountLink(event) {
  var senderID = event.sender.id;
  var recipientID = event.recipient.id;

  var status = event.account_linking.status;
  var authCode = event.account_linking.authorization_code;

  console.log("Received account link event with for user %d with status %s " +
    "and auth code %s ", senderID, status, authCode);
}

/*
 * Send an image using the Send API.
 *
 */
function sendImageMessage(recipientId) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      attachment: {
        type: "image",
        payload: {
          url: SERVER_URL + "/assets/rift.png"
        }
      }
    }
  };

  callSendAPI(messageData);
}


/*
 * Send a text message using the Send API.
 *
 */
function sendTextMessage(recipientId, messageText) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      text: messageText,
      metadata: "DEVELOPER_DEFINED_METADATA"
    }
  };

  callSendAPI(messageData);
}

/*
 * Send a button message using the Send API.
 *
 */
function sendButtonMessage(recipientId) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      attachment: {
        type: "template",
        payload: {
          template_type: "button",
          text: "This is test text",
          buttons:[{
            type: "web_url",
            url: "https://www.oculus.com/en-us/rift/",
            title: "Open Web URL"
          }, {
            type: "postback",
            title: "Trigger Postback",
            payload: "DEVELOPER_DEFINED_PAYLOAD"
          }, {
            type: "phone_number",
            title: "Call Phone Number",
            payload: "+16505551234"
          }]
        }
      }
    }
  };  

  callSendAPI(messageData);
}

/*
 * Send a Structured Message (Generic Message type) using the Send API.
 *
 */
function sendGenericMessage(recipientId) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      attachment: {
        type: "template",
        payload: {
          template_type: "generic",
          elements: [{
            title: "rift",
            subtitle: "Next-generation virtual reality",
            item_url: "https://www.oculus.com/en-us/rift/",               
            image_url: SERVER_URL + "/assets/rift.png",
            buttons: [{
              type: "web_url",
              url: "https://www.oculus.com/en-us/rift/",
              title: "Open Web URL"
            }, {
              type: "postback",
              title: "Call Postback",
              payload: "Payload for first bubble",
            }],
          }, {
            title: "touch",
            subtitle: "Your Hands, Now in VR",
            item_url: "https://www.oculus.com/en-us/touch/",               
            image_url: SERVER_URL + "/assets/touch.png",
            buttons: [{
              type: "web_url",
              url: "https://www.oculus.com/en-us/touch/",
              title: "Open Web URL"
            }, {
              type: "postback",
              title: "Call Postback",
              payload: "Payload for second bubble",
            }]
          }]
        }
      }
    }
  };  

  callSendAPI(messageData);
}

/*
 * Send a receipt message using the Send API.
 *
 */
function sendReceiptMessage(recipientId) {
  // Generate a random receipt ID as the API requires a unique ID
  var receiptId = "order" + Math.floor(Math.random()*1000);

  var messageData = {
    recipient: {
      id: recipientId
    },
    message:{
      attachment: {
        type: "template",
        payload: {
          template_type: "receipt",
          recipient_name: "Peter Chang",
          order_number: receiptId,
          currency: "USD",
          payment_method: "Visa 1234",        
          timestamp: "1428444852", 
          elements: [{
            title: "Oculus Rift",
            subtitle: "Includes: headset, sensor, remote",
            quantity: 1,
            price: 599.00,
            currency: "USD",
            image_url: SERVER_URL + "/assets/riftsq.png"
          }, {
            title: "Samsung Gear VR",
            subtitle: "Frost White",
            quantity: 1,
            price: 99.99,
            currency: "USD",
            image_url: SERVER_URL + "/assets/gearvrsq.png"
          }],
          address: {
            street_1: "1 Hacker Way",
            street_2: "",
            city: "Menlo Park",
            postal_code: "94025",
            state: "CA",
            country: "US"
          },
          summary: {
            subtotal: 698.99,
            shipping_cost: 20.00,
            total_tax: 57.67,
            total_cost: 626.66
          },
          adjustments: [{
            name: "New Customer Discount",
            amount: -50
          }, {
            name: "$100 Off Coupon",
            amount: -100
          }]
        }
      }
    }
  };

  callSendAPI(messageData);
}

/*
 * Send a message with Quick Reply buttons.
 *
 */
function sendQuickReply(recipientId) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      text: "What's your favorite movie genre?",
      quick_replies: [
        {
          "content_type":"text",
          "title":"Action",
          "payload":"DEVELOPER_DEFINED_PAYLOAD_FOR_PICKING_ACTION"
        },
        {
          "content_type":"text",
          "title":"Comedy",
          "payload":"DEVELOPER_DEFINED_PAYLOAD_FOR_PICKING_COMEDY"
        },
        {
          "content_type":"text",
          "title":"Drama",
          "payload":"DEVELOPER_DEFINED_PAYLOAD_FOR_PICKING_DRAMA"
        }
      ]
    }
  };

  callSendAPI(messageData);
}

/*
 * Send a read receipt to indicate the message has been read
 *
 */
function sendReadReceipt(recipientId) {
  console.log("Sending a read receipt to mark message as seen");

  var messageData = {
    recipient: {
      id: recipientId
    },
    sender_action: "mark_seen"
  };

  callSendAPI(messageData);
}

/*
 * Turn typing indicator on
 *
 */
function sendTypingOn(recipientId) {
  console.log("Turning typing indicator on");

  var messageData = {
    recipient: {
      id: recipientId
    },
    sender_action: "typing_on"
  };

  callSendAPI(messageData);
}

/*
 * Turn typing indicator off
 *
 */
function sendTypingOff(recipientId) {
  console.log("Turning typing indicator off");

  var messageData = {
    recipient: {
      id: recipientId
    },
    sender_action: "typing_off"
  };

  callSendAPI(messageData);
}

/*
 * Send a message with the account linking call-to-action
 *
 */
function sendAccountLinking(recipientId) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      attachment: {
        type: "template",
        payload: {
          template_type: "button",
          text: "Welcome. Link your account.",
          buttons:[{
            type: "account_link",
            url: SERVER_URL + "/authorize"
          }]
        }
      }
    }
  };  

  callSendAPI(messageData);
}

/*
 * Call the Send API. The message data goes in the body. If successful, we'll 
 * get the message id in a response 
 *
 */
function callSendAPI(messageData) {
  request({
    uri: 'https://graph.facebook.com/v2.6/me/messages',
    qs: { access_token: PAGE_ACCESS_TOKEN },
    method: 'POST',
    json: messageData

  }, function (error, response, body) {
    if (!error && response.statusCode == 200) {
      var recipientId = body.recipient_id;
      var messageId = body.message_id;

      if (messageId) {
        console.log("Successfully sent message with id %s to recipient %s", 
          messageId, recipientId);
      } else {
      console.log("Successfully called Send API for recipient %s", 
        recipientId);
      }
    } else {
      console.error("Failed calling Send API", response.statusCode, response.statusMessage, body.error);
    }
  });  
}

// Start server
// Webhooks must be available via SSL with a certificate signed by a valid 
// certificate authority.
app.listen(app.get('port'), function() {
  console.log('Node app is running on port', app.get('port'));
});

module.exports = app;

