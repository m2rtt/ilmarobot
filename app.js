/*
 * Copyright 2016-present, Facebook, Inc.
 * All rights reserved.
 *
 * This source code is licensed under the license found in the
 * LICENSE file in the root directory of this source tree.
 *
 * Ilmateadustaja bot Messengerile, FB baaskoodi muutis Märt Sessman.
 * Kasutab OpenWeatherMap API andmeid ja jookseb Heroku serveris.
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

// freim
var dict = {};

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
app.post('/webhook', function(req, res) {
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
                    //receivedDeliveryConfirmation(messagingEvent);
                } else if (messagingEvent.postback) {
                    //receivedPostback(messagingEvent);
                } else if (messagingEvent.read) {
                    //receivedMessageRead(messagingEvent);
                } else if (messagingEvent.account_linking) {
                    //receivedAccountLink(messagingEvent);
                } else {
                    console.log("Webhook received unknown messagingEvent: ", messagingEvent);
                }
            });
        });

        // Assume all went well.
        //
        // You must send back a 200, within 20 seconds, to let us know you've 
        // successfully received the callback. Otherwise, the request will time out.
        console.log("here");
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
        dict[senderID] = { 'aeg': 'hetkel', 'x': 0 };
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
    var linnaPattern = /[A-ZŽŠÕÄÖÜ][a-zžšõäöü]+((( |-)[A-ZŽŠÕÄÖÜa-zžšõäöü][a-zžšõäöü]+)*( |-)[A-ZŽŠÕÄÖÜ][a-zžšõäöü]+)?/;
    if (messageText) {
        if (messageText.match(/[tT]ere|[Hh]ei|[Tt]sau|[Tt]erv/)) {
            sendTextMessage(senderID, "Tere!\nKüsi minult ilma kohta Eesti asulates ja linnades. Tean öelda ilma nii tänase, homse kui ka ülehomse kohta.");
        } else if (messageText.match(/[Nn]ägemist|[Hh]ead aega|[Hh]üvasti/)) {
            sendTextMessage(senderID, "Nägemist!");
        } else if (messageText.match(/[Aa]itäh|[Tt]änan|[Tt]änud/)) {
            sendTextMessage(senderID, "Pole tänu väärt, aitan alati");
        }
        // eemaldame esimese tähe, sest lause algus. Eeldame, et linna nime lause alguses ei kasutata.
        else if (messageText.substring(1).match(linnaPattern)) {
            var linn = messageText.substring(1).match(linnaPattern)[0];
            getLinnanimi(linn, senderID, function(cb) {
                console.log("getLinnanimi callback: " + cb);
                dict[senderID]['linn'] = linn;
                getIlmateade(linn, cb, senderID, messageText, true);
            });
        } else if (dict[senderID]['linn'] != undefined) {
            kontrollLaused(messageText, senderID, false);
        } else {
            var response = "Ma ei saa teist hästi aru.\n";
            response += "\nMärksõnu, mida ära tunnen: temperatuur, õhurõhk, õhuniiskus, tuulesuund, tuulekiirus, tuul. \n";
            response += "Oskan vastata ka ilma kohta homme või ülehomme hommikul, päeval, õhtul.";
            sendTextMessage(senderID, response);
        }

    } else if (messageAttachments) {
        sendTextMessage(senderID, "Mulle ei tasu midagi saata. Küsi parem ilma kohta.");
    }
}

function getIlmateade(orig, linn, uid, text, linnChanged) {
    getIlmJSON(linn, uid, function(cb) {
        if (!cb || !cb['list']) {
            if (dict[uid].x < 5) {
                dict[uid].x += 1;
                console.log("ilmateate hankimine vigane");
                getIlmateade(orig, linn, uid, text, linnChanged);
            } else {
                dict[uid].x = 0;
                sendTextMessage(uid, "Ilmateadet ei suutnud hankida. Veenduge, et linna nimi on õige.");
            }
        } else {
            dict[uid]['ilm'] = cb;
            kontrollLaused(text, uid, linnChanged);
        }
    });
}

function kontrollLaused(messageText, senderID, linnChanged) {
    var response = 'Ma ei saa teist aru';
    var check = false;
    if (messageText.match(/ilm.*/i)) {
        dict[senderID]['viimane'] = 'ilm';
        if (dict[senderID]['linn'] == undefined)
            response = "Täpsustage linna nimi.";
        else
            response = getIlmText(dict[senderID]['linn'], dict[senderID]['ilm'], dict[senderID]['aeg'])
    }
    if (messageText.match(/(õhu)?niiskus.*/i)) {
        dict[senderID]['viimane'] = 'õhuniiskus';
        if (dict[senderID]['linn'] == undefined)
            response = "Täpsustage linna nimi.";
        else
            response = getÕhuniiskusText(dict[senderID]['linn'],
                dict[senderID]['ilm']['list'][getAegIndex(dict[senderID]['ilm'], dict[senderID]['aeg'])]['main']['humidity'],
                dict[senderID]['aeg']);
    }
    if (messageText.match(/temperatuur|kraad|sooja|külm.*|soe/i)) {
        dict[senderID]['viimane'] = 'temperatuur';
        if (dict[senderID]['linn'] == undefined)
            response = "Täpsustage linna nimi.";
        else
            response = getTemperatuurText(dict[senderID]['linn'],
                dict[senderID]['ilm']['list'][getAegIndex(dict[senderID]['ilm'], dict[senderID]['aeg'])]['main']['temp'],
                dict[senderID]['aeg']);
    }
    if (messageText.match(/(õhu)?rõhk/i)) {
        dict[senderID]['viimane'] = 'õhurõhk';
        if (dict[senderID]['linn'] == undefined)
            response = "Täpsustage linna nimi.";
        else
            response = getÕhurõhkText(dict[senderID]['linn'],
                dict[senderID]['ilm']['list'][getAegIndex(dict[senderID]['ilm'], dict[senderID]['aeg'])]['main']['pressure'],
                dict[senderID]['aeg']);
    }
    if (messageText.match(/tuul/i)) {
        dict[senderID]['viimane'] = 'tuul';
        if (messageText.match(/suun.*/i)) {
            dict[senderID]['viimane'] = 'tuulesuund';
            if (messageText.match(/kiirus|kiire/i))
                dict[senderID]['viimane'] = 'tuul';
        }
        if (messageText.match(/kiirus|kiire/i) && !messageText.match(/suun.*/i))
            dict[senderID]['viimane'] = 'tuulekiirus';
        if (dict[senderID]['linn'] == undefined)
            response = "Täpsustage linna nimi."
        else
            response = getTuulText(dict[senderID]['linn'], dict[senderID]['ilm'], dict[senderID]['viimane'], dict[senderID]['aeg'], senderID)
    }
    if (messageText.match(/täna|hetkel|praegu|nüüd/i)) {
        dict[senderID]['aeg'] = 'hetkel';
        if (dict[senderID]['linn'] != undefined && dict[senderID]['ilm'] != undefined) {
            response = getYldineIlm(dict[senderID]['ilm'], dict[senderID]['linn'], dict[senderID]['aeg'], senderID);
        }
    }
    if (messageText.match(/õhtu|öö/i)) {
        dict[senderID]['aeg'] = 'õhtu';
        if (dict[senderID]['linn'] != undefined && dict[senderID]['ilm'] != undefined) {
            response = getYldineIlm(dict[senderID]['ilm'], dict[senderID]['linn'], dict[senderID]['aeg'], senderID);
        }
    }
    if (messageText.match(/lõuna|päev/i)) {
        dict[senderID]['aeg'] = 'päev';
        if (dict[senderID]['linn'] != undefined && dict[senderID]['ilm'] != undefined) {
            response = getYldineIlm(dict[senderID]['ilm'], dict[senderID]['linn'], dict[senderID]['aeg'], senderID);
        }
    }
    if (messageText.match(/homme|homne/i)) {
        dict[senderID]['aeg'] = 'hommepäev';
        if (messageText.match(/hommik/i))
            dict[senderID]['aeg'] = 'hommehommik';
        if (messageText.match(/õhtu|öö/i))
            dict[senderID]['aeg'] = 'hommeõhtu';
        if (dict[senderID]['linn'] != undefined && dict[senderID]['ilm'] != undefined) {
            response = getYldineIlm(dict[senderID]['ilm'], dict[senderID]['linn'], dict[senderID]['aeg'], senderID);
        }
    }
    if (messageText.match(/üle(homme|homne)/i)) {
        dict[senderID]['aeg'] = 'ülehommepäev';
        if (messageText.match(/hommik/i))
            dict[senderID]['aeg'] = 'ülehommehommik';
        if (messageText.match(/õhtu|öö/i))
            dict[senderID]['aeg'] = 'ülehommeõhtu';
        if (dict[senderID]['linn'] != undefined && dict[senderID]['ilm'] != undefined) {
            response = getYldineIlm(dict[senderID]['ilm'], dict[senderID]['linn'], dict[senderID]['aeg'], senderID);
            check = true;
        }
    }
    if (response == 'Ma ei saa teist aru') {
        if (!linnChanged) {
            response += "\nMärksõnu, mida ära tunnen: temperatuur, õhurõhk, õhuniiskus, tuulesuund, tuulekiirus, tuul. \n";
            response += "Oskan vastata ka ilma kohta homme või ülehomme hommikul, päeval, õhtul.";
        } else {
            response = getYldineIlm(dict[senderID]['ilm'], dict[senderID]['linn'], dict[senderID]['aeg'], senderID);
        }
    }
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
    var tText = "";
    if (temp >= 0)
        tText = "sooja";
    else
        tText = "külma";
    if (getIlmKirjeldus(linn, ilm, i) == "")
        t == " ";
    else
        t = " " + getIlmKirjeldus(linn, ilm, i) + ", "
    return getAegText(aeg) + t + tText + " on " + Math.abs(temp) + " kraadi, puhub " + getTuulesuund(tuulesuund) + "tuul kiirusega " + kiirus + " m/s, õhurõhk on " + pressure + " hPa ja õhuniiskus " + niiskus + "%";
}

function getÕhuniiskusText(linn, niiskus, aeg) {
    return linn + " on " + getAegText(aeg).toLowerCase() + " õhuniiskust " + niiskus + "%";
}

function getTemperatuurText(linn, temp, aeg) {
    var t = "";
    if (temp >= 0)
        t = "sooja";
    else
        t = "külma";
    return linn + " on " + getAegText(aeg).toLowerCase() + " " + Math.abs(temp) + " kraadi " + t;
}

function getÕhurõhkText(linn, pressure, aeg) {
    return linn + " on " + getAegText(aeg).toLowerCase() + " õhurõhk " + pressure + " hPa";
}

function getTuulText(linn, ilm, viimane, aeg, uid) {
    var response = "";
    var tuulesuund = ilm['list'][getAegIndex(ilm, aeg)]['wind']['deg'];
    var kiirus = ilm['list'][getAegIndex(ilm, aeg)]['wind']['speed'];
    var t = getTuulesuund(tuulesuund);
    if (dict[uid]['viimane'] == "tuulesuund")
        response = linn + " puhub " + getAegText(aeg).toLowerCase() + " " + t + "tuul.";
    else if (dict[uid]['viimane'] == "tuul")
        response = linn + " puhub " + getAegText(aeg).toLowerCase() + " " + t + "tuul " + kiirus + " m/s";
    else if (dict[uid]['viimane'] == "tuulekiirus")
        response = linn + " puhub " + getAegText(aeg).toLowerCase() + " tuul kiirusega " + kiirus + " m/s";
    return response;
}

function getTuulesuund(deg) {
    var t = "";
    if (deg >= 337.5 && deg <= 360.0 || deg < 22.5 && deg >= 0.0)
        t = "põhja";
    else if (deg >= 22.5 && deg < 67.5)
        t = "kirde";
    else if (deg >= 67.5 && deg < 112.5)
        t = "ida";
    else if (deg >= 112.5 && deg < 157.5)
        t = "kagu";
    else if (deg >= 157.5 && deg < 202.5)
        t = "lõuna";
    else if (deg >= 202.5 && deg < 247.5)
        t = "edela";
    else if (deg >= 247.5 && deg < 292.5)
        t = "lääne";
    else if (deg >= 292.5 && deg < 337.5)
        t = "loode";
    return t;
}

function getIlmKirjeldus(linn, ilm, index) {
    var desc = ilm['list'][index]['weather'][0]['main']
    if (desc == "Thunderstorm")
        return "on " + linn + " äike";
    if (desc == "Drizzle")
        return "sajab " + linn + " uduvihma";
    if (desc == "Rain")
        return "sajab " + linn + " vihma";
    if (desc == "Snow")
        return "sajab " + linn + " lund";
    if (desc == "Clouds")
        return "on " + linn + " pilves ilm";
    if (desc == "Clear")
        return "on " + linn + " selge taevas";
    if (desc == "Extreme")
        return "on " + linn + " ekstreemsed olud";
    if (desc == "Atmosphere")
        return "on " + linn + " udu"; //see ei ole kindlasti alati correct
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
        } else if (aeg == "õhtu") {
            if (p == date.getDate()) {
                if (k == 21)
                    return i
            }
        } else if (aeg == "hommehommik") {
            if (p == date.getDate() + 1) {
                if (k == 9)
                    return i
            }
        } else if (aeg == "hommepäev") {
            if (p == date.getDate() + 1) {
                if (k == 15)
                    return i
            }
        } else if (aeg == "hommeõhtu") {
            if (p == date.getDate() + 1) {
                if (k == 21)
                    return i
            }
        } else if (aeg == "ülehommehommik") {
            if (p == date.getDate() + 2) {
                if (k == 9)
                    return i
            }
        } else if (aeg == "ülehommepäev") {
            if (p == date.getDate() + 2) {
                if (k == 15)
                    return i
            }
        } else if (aeg == "ülehommeõhtu") {
            if (p == date.getDate() + 2) {
                if (k == 21)
                    return i
            }
        }
    }
    return 0;
}

function getLinnanimi(linn, uid, callback) {
    sendTypingOn(uid);
    var encodedLinn = encodeURIComponent(linn);
    request('http://prog.keeleressursid.ee/ws_etmrf/lemma.php?s=' + encodedLinn, getLemma);

    function getLemma(err, res, body) {
        if (!err && res.statusCode < 400) {
            var retData = JSON.parse(body);
            var nimi;
            if (!retData)
                nimi = linn;
            else
                nimi = retData['root']; // käändes, siis tagastame tüve
            request('https://glosbe.com/gapi/translate?from=est&dest=eng&format=json&phrase=' + encodeURIComponent(nimi), getTranslation);

            function getTranslation(err, res, body) {
                if (!err && res.statusCode < 400) {
                    var retData = JSON.parse(body);
                    var nimi;
                    if (retData['tuc'].length > 0)
                        callback(retData['tuc'][0]['phrase']['text'])
                    else
                        callback(retData['phrase']);
                    sendTypingOff(uid);
                }
            }
        } else {
            console.log(err);
            console.log(res.statusCode);
        }
    }
}

function getIlmJSON(linn, uid, callback) {
    var encodedLinn = encodeURIComponent(linn);
    var apiKey = 'da4e1bd6fbe3a91e49486215b059c31a';
    //var parser = new xml2js.Parser();
    sendTypingOn(uid);
    request('http://api.openweathermap.org/data/2.5/forecast?APPID=' + apiKey + '&q=' + encodedLinn + '&units=metric', getIlm);

    function getIlm(err, response, body) {
        if (!err && response.statusCode < 400) {
            var retData = body;
            console.log(body);
            dict[uid]['ilm'] = retData;
            if (!retData)
                sendTextMessage(uid, "Probleem ilmateate hankimisega :(");
            else
                callback(retData);
            sendTypingOff(uid);
        } else {
            console.log(err);
            console.log(response.statusCode);
        }
    }
}
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
            metadata: ".."
        }
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

    }, function(error, response, body) {
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