// Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

var Slot = entd.crypto.Pkcs11.Slot;
var Token = entd.crypto.Pkcs11.Token;
var Session = entd.crypto.Pkcs11.Session;
var Object = entd.crypto.Pkcs11.Object;

const TEST_USER_PIN = "111111";

// Public key.
const MODULUS =
  "CB78D8AA4BF290AC26402FF120B22246F63E1A49DB4E05CD2AD580A86E8F4E93C903EE" +
  "BC1E6A17419AEEBCAFDD08C7D9A7202E4A6C6F0AAA7F661E6F607B8FB1880D07EBFBE0" +
  "0930F565576A236CBB8DDED6E9B3E4B9679B2613AAC140D237037DF4CBC91D1551DC0C" +
  "1C185A0DC158FBA85D41102C89A6DEFC21B4D4855C12BF6B6563DA8F07A799D9BB3FF6" +
  "7BC7978A2FF19D4D0E63DA48B0754DCC3444F5E0EA756A9867237E25868A08DA22FC30" +
  "7BF2A8C06D0FA0D4064B1897298ED150B7EFDF82416569A201854ED392EBA66171150C" +
  "24AD80B1F0F28DEB7C954204D38EAADFE57F0458AE6523ABB2E0F68DCC5FABD55DF8C9" +
  "65F69368D24E6FFAE284CD";

// Private key.
const PRIV_EXP =
  "008B6B50BACFB373A221CB958E19A3358D7E28EB8673F8B04CF6EEB86BB0E60D278273" +
  "6960094F1484658EF44764A3219D67C0CB373FB98E8B692425F2971FD344083F359063" +
  "540DB8384DAA6A15BFE97BBA97742749B028E7CC5D698165D324D305B978F163363A93" +
  "16D12176833A5AA885A2F0740EB07B610B4E6543C1E56709FC05706A172F8A4FBA7445" +
  "09C0FC20DFB6AC0D811AD17B55B065F776EAAA8716D3D88D05D224C35C252A9F2F4964" +
  "3EE043021A77A244A1F0FF6836907051A7089F947328D44466D328C17A132F767A8215" +
  "A1CD7330AC8A7DA99A61ABE43F76948B5F1953A84BBC3BD045D14E04EA6CD7F0BF8F94" +
  "F66C8E114993D78D478C4AD9";
const PRIME_1 =
  "00FE6401FBDF87BF57A7E051A50CA724D17D5675ECBD88D9527CC6F63EAABC27364EF3" +
  "5B143A31CD9673CD297296B15078E194E0F7C40D64CC5AE4000694D1FD6FF426E54A51" +
  "CC7E2FA546C3F5AB54EC30509ABE2B1A92CF8FCD53CAB77BB7D51DE4924B41C39E0C3E" +
  "9232ED3B993287DA8D5B2E186DA4A9902C129EDCA773A10B";
const PRIME_2 =
  "00CCC25FE66B0900BDF17B57C574E29E3B19AD85519B1F43A49A2917A4540A91FABB86" +
  "FB2C7AB030BAFD37F65852D7AEE704FA7C09ABDF4CAB91FFA1508558DDA0662EE0AEEE" +
  "3B7D8D894EAD7FF0BCAAD9434C399D9A378EB111BFB505E2C91E4BE9DDE2BCD9A97E68" +
  "C355422CD3650A4A3B6DC4CFFC567FD1AD352953A448C887";
const KEY_EXP_1 =
  "2F217C349C0F5C65F3165E4A03F41BA02C668E66941EFC9489C59AEDB55832B39F20FB" +
  "28DE3747EDADFABEC91A1E33D89182B1C375B13D9196ED530BE51A9AA7D9463388F76A" +
  "B99E3E32C42F89D4AC05AF895BDE44881AA87BD42064AA293EF4D0DA41D32758EACFD4" +
  "EA56858A369070EF6B8B38BF67987ABB8F9F9B25F3084D";
const KEY_EXP_2 =
  "7AFE0EA8D38656E1C159BB812A12ADC506498A99583A516160106AD9147A3CF1850F31" +
  "74A845891FE8D662ACEF260B334D74406976C9ECBDEA36C8E91B1024202300E9896A24" +
  "65E84C9FEBEBBBE9381EC523D63FEAD0906FA01FAD56D9C0C0E80C94718BCA9ADB0986" +
  "BB81C277406C0BE6E2AAA3DC0901422B6E9162627E2DA5";
const COEF =
  "63DD875B0D3BE89F341790A4EE4F68D739F49EED2D30F701E1E2F0B99448111C6074E6" +
  "7E46189358808C811D26404F142E3C650C390FFB836DC1C5560400813DDFEB84476113" +
  "472B5F262EB0F4178C7F08CF8EE0CCEBEBE54E89314172AC1A17C83415CBA4E5C4A488" +
  "AE88557EAB8B7725FD4407FD4279C6AEAE3E8C9B28AF75";

// X.509 certificate.
const CERT_DATA =
  "308203B53082029DA003020102020900979D8DA71DBE42FF300D06092A864886F70D01" +
  "010505003045310B3009060355040613024155311330110603550408130A536F6D652D" +
  "53746174653121301F060355040A1318496E7465726E65742057696467697473205074" +
  "79204C7464301E170D3130313131393232343732305A170D3130313231393232343732" +
  "305A3045310B3009060355040613024155311330110603550408130A536F6D652D5374" +
  "6174653121301F060355040A1318496E7465726E657420576964676974732050747920" +
  "4C746430820122300D06092A864886F70D01010105000382010F003082010A02820101" +
  "00CB78D8AA4BF290AC26402FF120B22246F63E1A49DB4E05CD2AD580A86E8F4E93C903" +
  "EEBC1E6A17419AEEBCAFDD08C7D9A7202E4A6C6F0AAA7F661E6F607B8FB1880D07EBFB" +
  "E00930F565576A236CBB8DDED6E9B3E4B9679B2613AAC140D237037DF4CBC91D1551DC" +
  "0C1C185A0DC158FBA85D41102C89A6DEFC21B4D4855C12BF6B6563DA8F07A799D9BB3F" +
  "F67BC7978A2FF19D4D0E63DA48B0754DCC3444F5E0EA756A9867237E25868A08DA22FC" +
  "307BF2A8C06D0FA0D4064B1897298ED150B7EFDF82416569A201854ED392EBA6617115" +
  "0C24AD80B1F0F28DEB7C954204D38EAADFE57F0458AE6523ABB2E0F68DCC5FABD55DF8" +
  "C965F69368D24E6FFAE284CD0203010001A381A73081A4301D0603551D0E04160414B6" +
  "77B9FCA5111F646E91A7DF6B31B600D341D91B30750603551D23046E306C8014B677B9" +
  "FCA5111F646E91A7DF6B31B600D341D91BA149A4473045310B30090603550406130241" +
  "55311330110603550408130A536F6D652D53746174653121301F060355040A1318496E" +
  "7465726E6574205769646769747320507479204C7464820900979D8DA71DBE42FF300C" +
  "0603551D13040530030101FF300D06092A864886F70D01010505000382010100A4B0DD" +
  "DB579C0AA68A0ABAF6A32D537389C0A25FF85D11D22C84A723B348856081E5A6E99218" +
  "AEDEB2BAC9704F906B436EBBA2E2B521EDCC42083C69931E1EF792CFBEA99086ED5B54" +
  "A38B121377A31439075FE61E21B1CB36BE25C31D9B23DE59993CEC369F304A596DF218" +
  "AB9E55A0476EF1B98D01D787B445AABF0B816C2897C08AA733619B70BCDCA7AEC2EA1B" +
  "85C56A968AF24230DF70D3EE2CD93C150169E5A7649B7EE64DC6FFE952CE7613A281AF" +
  "9987A3C3A3761D6CBA618AC1744FB9B9B7A59492C8C47917BE68945537B4151DCD73B5" +
  "C1241B2CEFEDFFBFE88F60B2C60AA0BCABE27DFF97FE738306DA94A2C3F5FD4DD591ED" +
  "28386FAC26D5EF2D";

function findObjects(session, id, label, type) {
  if (id != null && label != null) {
    return session.findObjects(
      [
        [Object.CKA_CLASS, type],
        [Object.CKA_ID, id],
        [Object.CKA_LABEL, label]
      ]
    );
  } else if (id != null) {
    return session.findObjects(
      [
        [Object.CKA_CLASS, type],
        [Object.CKA_ID, id]
      ]
    );
  } else if (label != null) {
    return session.findObjects(
      [
        [Object.CKA_CLASS, type],
        [Object.CKA_LABEL, label]
      ]
    );
  } else {
    return println("Invalid test argument");
  }
}

function createPublicKey(session, id, label) {
  session.createObject(
    [
      [Object.CKA_LABEL, label],
      [Object.CKA_ID, id],
      [Object.CKA_TOKEN, true],
      [Object.CKA_CLASS, Object.CKO_PUBLIC_KEY],
      [Object.CKA_KEY_TYPE, Object.CKK_RSA],
      [Object.CKA_WRAP, true],
      [Object.CKA_MODULUS, MODULUS]
    ]
  );
}

function createPrivateKey(session, id, label) {
  session.createObject(
    [
      [Object.CKA_LABEL, label],
      [Object.CKA_ID, id],
      [Object.CKA_TOKEN, true],
      [Object.CKA_CLASS, Object.CKO_PRIVATE_KEY],
      [Object.CKA_KEY_TYPE, Object.CKK_RSA],
      [Object.CKA_PRIVATE, true],
      [Object.CKA_SENSITIVE, true],
      [Object.CKA_SIGN, true],
      [Object.CKA_DECRYPT, true],
      [Object.CKA_UNWRAP, true],
      [Object.CKA_PRIME_1, PRIME_1],
      [Object.CKA_PRIME_2, PRIME_2],
      [Object.CKA_EXPONENT_1, KEY_EXP_1],
      [Object.CKA_EXPONENT_2, KEY_EXP_2],
      [Object.CKA_PRIVATE_EXPONENT, PRIV_EXP],
      [Object.CKA_COEFFICIENT, COEF],
      [Object.CKA_MODULUS, MODULUS]
    ]
  );
}

function createCertificate(session, id, label) {
  session.createObject(
    [
      [Object.CKA_LABEL, label],
      [Object.CKA_ID, id],
      [Object.CKA_TOKEN, true],
      [Object.CKA_CLASS, Object.CKO_CERTIFICATE],
      [Object.CKA_SUBJECT, "/CN=nelsona@chromium.org"],
      [Object.CKA_CERTIFICATE_TYPE, Object.CKC_X_509],
      [Object.CKA_VALUE, CERT_DATA]
    ]
  );
}


function testFindObject(what, session, find_id, find_label, type) {
  var result;

  // Positive tests.
  try {
    // Search for ID + label.
    result = findObjects(session, find_id, find_label, type) || null;
    if (result == null || result.length > 1)
      return println("Found too much " + what + "s (id + label)");
    if (result == null || result.length != 1)
      return println("Did not find " + what + " (id + label)");

    // Search for ID only.
    result = findObjects(session, find_id, null, type) || null;
    if (result == null || result.length > 1)
      return println("Found too much " + what + "s (id)");
    if (result == null || result.length != 1)
      return println("Did not find " + what + " (id)");

    // Search for label only.
    result = findObjects(session, null, find_label, type) || null;
    if (result == null || result.length > 1)
      return println("Found too much " + what + "s (label)");
    if (result == null || result.length != 1)
      return println("Did not find " + what + " (label)");
  } catch(ex) {
    return println("Failed to search for " + what + ": " + ex);
  }

  if (!(result[0] instanceof Object)) {
    return println("Incorrect object returned by FindObjects");
  }

  return result[0];
}

entd.onLoad = function () {

  var pkcs11 = new entd.crypto.Pkcs11();

  var slot = pkcs11.slots[0];

  if (!(slot.flags & Slot.CKF_TOKEN_PRESENT))
    return println("Expected slot 0 to have a token present");

  var token = slot.token;

  if (!(token instanceof Token))
    return println("Expected instanceof entd.Pkcs11.Token");

  var session = null;
  try {
    token.closeAllSessions();
    session = token.openSession(Token.CKF_RW_SESSION);
  } catch (ex) {
    println('Unable to open session: ' + ex);
    return false;
  }

  if (!(session instanceof Session))
    return println("Expected instanceof entd.Pkcs11.Session");

  try {
    if (!session.login(Session.CKU_USER, TEST_USER_PIN)) {
      println('Unable to log in user into token');
      session.close();
      return false;
    }
  } catch (ex) {
    println('Failed to login user into token: ' + ex);
    session.close();
    return false;
  }

  // Create public key.
  entd.syslog.info("Testing RSA public key creation");
  var pubkey_label = "KEY_TO_CREATE_PUBLIC";
  var pubkey_id = "55667788";
  try {
    createPublicKey(session, pubkey_id, pubkey_label);
  } catch(ex) {
    return println("Expected to create public key: " + ex);
  }
  if (!testFindObject("public key", session, pubkey_id, pubkey_label,
                   Object.CKO_PUBLIC_KEY)) {
    return;
  }

  // Create private key.
  entd.syslog.info("Testing RSA private key creation");

  var privkey_label = "KEY_TO_CREATE_PRIVATE";
  var privkey_id = "BABA1975";

  try {
    createPrivateKey(session, privkey_id, privkey_label);
  } catch(ex) {
    return println("Expected to create private key: " + ex);
  }
  if (!testFindObject("private key", session, privkey_id, privkey_label,
                   Object.CKO_PRIVATE_KEY)) {
    return;
  }

  // Create certificate.
  entd.syslog.info("Testing X.509 certificate creation");
  var cert_label = "CERTIFICATE_TO_CREATE";
  var cert_id = "CE00EC";
  try {
    createCertificate(session, cert_id, cert_label);
  } catch(ex) {
    return println("Expected to create certificate: " + ex);
  }
  if (!testFindObject("certificate", session, cert_id, cert_label,
                   Object.CKO_CERTIFICATE)) {
    return;
  }

  // Object deletion.
  try {
    entd.syslog.info("Deleting all objects created");
    var private_key = testFindObject("private key", session, privkey_id,
                                     privkey_label, Object.CKO_PRIVATE_KEY);
    private_key.destroy();
  } catch(ex) {
    return println("Failed to delete private key: " + ex);
  }
  try {
    var public_key = testFindObject("public key", session, pubkey_id,
                                     pubkey_label, Object.CKO_PUBLIC_KEY);
    public_key.destroy();
  } catch(ex) {
    return println("Failed to delete public key: " + ex);
  }
  try {
    var certificate = testFindObject("certificate", session, cert_id,
                                     cert_label, Object.CKO_CERTIFICATE);
    certificate.destroy();
  } catch(ex) {
    return println("Failed to delete certificate: " + ex);
  }

  println("LOOKS OK");
}
