/**
 * Interface strings.
 *
 * Security wording is the part that matters most here. A warning that is
 * vague ("something changed") or alarming without being actionable ("SECURITY
 * ERROR") both fail the same way: the user dismisses it. Every security string
 * below says what happened, what it might mean, and what to do.
 */

export type Locale = 'en' | 'tr';

export interface Strings {
  appName: string;

  // Onboarding
  welcomeTitle: string;
  welcomeBody: string;
  createAccount: string;
  creatingAccount: string;
  deviceNameLabel: string;
  deviceNamePlaceholder: string;
  deviceNameHelp: string;
  yourNameLabel: string;
  yourNamePlaceholder: string;
  yourNameHelp: string;
  aboutLabel: string;
  aboutPlaceholder: string;
  changePhoto: string;
  removePhoto: string;
  save: string;
  profileSaved: string;
  profile: string;
  linkDevice: string;
  linkDeviceBody: string;
  linkShowCode: string;
  linkScanCode: string;
  linkPairingCode: string;
  linkConfirm: string;
  linkWaiting: string;
  linkDone: string;
  joinExisting: string;
  joinTitle: string;
  joinBody: string;
  joinStart: string;
  joinShowThis: string;
  joinCompare: string;
  scan: string;
  scanHint: string;
  scanOrPaste: string;
  cameraPermissionTitle: string;
  cameraPermissionBody: string;
  cameraPermissionGrant: string;
  cameraPermissionDenied: string;
  verifyScanTitle: string;
  verifyScanMatch: string;
  verifyScanMismatch: string;
  attachPhoto: string;
  attachment: string;
  attachmentFailed: string;
  recordVoice: string;
  recording: string;
  play: string;
  pause: string;
  recoveryTitle: string;
  recoveryWarning: string;
  recoveryWritten: string;
  recoverTitle: string;
  recoverBody: string;
  recoverPlaceholder: string;
  recoverAction: string;
  recoverEntry: string;
  recoveryBody: string;
  recoveryConfirm: string;
  noPhoneNeeded: string;

  // Chat list
  chats: string;
  noChatsTitle: string;
  noChatsBody: string;
  newChat: string;
  searchPlaceholder: string;
  addContactTitle: string;
  addContactBody: string;
  accountIdOrHandle: string;
  start: string;

  // Conversation
  messagePlaceholder: string;
  send: string;
  encryptedNotice: string;
  sending: string;
  sent: string;
  delivered: string;
  read: string;
  failed: string;
  /** Shown in place of the subtitle while the other end is composing. */
  typing: string;
  privacyHeading: string;
  readReceiptsLabel: string;
  readReceiptsHelp: string;
  typingIndicatorsLabel: string;
  typingIndicatorsHelp: string;
  today: string;
  yesterday: string;

  // Verification
  verifyTitle: string;
  verifyBody: string;
  safetyNumber: string;
  markVerified: string;
  verified: string;
  notVerified: string;
  scanQr: string;

  // Identity change — the most important strings in the app
  identityChangedTitle: string;
  identityChangedBody: string;
  identityChangedAction: string;
  sendingBlocked: string;

  // Settings
  settings: string;
  yourAccountId: string;
  yourHandle: string;
  setHandle: string;
  copied: string;
  aboutSecurity: string;
  notAudited: string;
  signOut: string;

  // Errors
  errorNetwork: string;
  errorNoDevices: string;
  errorGeneric: string;
  /** Attribution for text the server chose; see `serverText`. */
  serverSaid: string;
  errorTransparency: string;
  errorSplitView: string;
  dismiss: string;
  newGroup: string;
  groupNameLabel: string;
  groupNamePlaceholder: string;
  groupMembersLabel: string;
  groupMembersHelp: string;
  groupCreate: string;
  groupNoContacts: string;
  groupBody: string;
  groupMembers: string;
  groupAdd: string;
  groupRemove: string;
  groupRemoveBody: string;
  groupYou: string;
  callAudio: string;
  callVideo: string;
  callRinging: string;
  callIncoming: string;
  callConnecting: string;
  callAnswer: string;
  callDecline: string;
  callHangUp: string;
  callMute: string;
  callUnmute: string;
  callVerified: string;
  callUnverified: string;
  callKeyChanged: string;
  callNoRelay: string;
  retry: string;
  cancel: string;
  copy: string;
  done: string;
}

const en: Strings = {
  appName: 'Tildra',

  welcomeTitle: 'Messaging that doesn’t ask who you are',
  welcomeBody:
    'Every chat is end-to-end encrypted by default. No phone number, no email — your account is a key that lives on this device.',
  createAccount: 'Create account',
  creatingAccount: 'Generating keys…',
  deviceNameLabel: 'Name this device',
  deviceNamePlaceholder: 'e.g. My phone',
  deviceNameHelp:
    'This one is stored on the server, so it can list your devices back to you. Name the phone, not yourself.',
  yourNameLabel: 'Your name',
  yourNamePlaceholder: 'What people should call you',
  yourNameHelp:
    'Only people you talk to see this. It is sent to them encrypted — the server never stores your name or picture.',
  aboutLabel: 'About',
  aboutPlaceholder: 'A line about you',
  changePhoto: 'Choose a photo',
  removePhoto: 'Remove photo',
  save: 'Save',
  profileSaved: 'Saved',
  profile: 'Profile',
  linkDevice: 'Add a device',
  linkDeviceBody:
    'On the new device, choose “Add a device” and paste the code it shows here. Then check that the six digits match on both screens before you carry on.',
  linkShowCode: 'Code for this device',
  linkScanCode: 'Paste the new device’s code',
  linkPairingCode: 'Pairing code',
  linkConfirm: 'The digits match',
  linkWaiting: 'Waiting for approval on your other device…',
  linkDone: 'Device linked',
  joinExisting: 'Add this device to an account I already have',
  joinTitle: 'Add this device',
  joinBody:
    'This device gets its own key. Show the code below to a device that is already signed in, then check that the six digits match on both screens before you continue.',
  joinStart: 'Show my code',
  joinShowThis: 'Show this to your other device',
  joinCompare:
    'Both screens must show these six digits. If they differ, stop — something is between your two devices.',
  scan: 'Scan a code',
  scanHint: 'Point the camera at the code on the other screen',
  scanOrPaste: 'or paste it instead',
  cameraPermissionTitle: 'Camera access',
  cameraPermissionBody:
    'Tildra reads the code off the other screen. Nothing is recorded and nothing is uploaded.',
  cameraPermissionGrant: 'Allow the camera',
  cameraPermissionDenied:
    'The camera is turned off for Tildra in your system settings. You can paste the code instead.',
  verifyScanTitle: 'Scan their code',
  verifyScanMatch: 'Verified. You are talking to the right device.',
  verifyScanMismatch:
    'That code does not match this conversation. Do not carry on until you know why — this is what a key substitution looks like.',
  attachPhoto: 'Send a photo',
  attachment: 'Attachment',
  attachmentFailed: 'Could not load this attachment.',
  recordVoice: 'Hold to record a voice message',
  recording: 'Recording…',
  play: 'Play',
  pause: 'Stop',
  recoveryTitle: 'Write down your recovery phrase',
  recoveryBody:
    'These 24 words are the only way back into your account. We cannot reset them for you — the server has nothing to reset. Store them somewhere physical.',
  recoveryConfirm: 'I’ve written it down',
  recoveryWarning:
    'Anyone holding these words is you. They are exactly as powerful as this unlocked phone — not a backup code, the account itself.',
  recoveryWritten: 'I have them somewhere safe',
  recoverTitle: 'Recover an account',
  recoverBody:
    'Type the 24 words. They are checked as you go, so a wrong word shows up before anything else happens.',
  recoverPlaceholder: 'word one, word two, …',
  recoverAction: 'Recover',
  recoverEntry: 'I have a recovery phrase',
  noPhoneNeeded: 'No phone number required',

  chats: 'Chats',
  noChatsTitle: 'No conversations yet',
  noChatsBody: 'Share your account ID with someone, or add theirs to start talking.',
  newChat: 'New chat',
  searchPlaceholder: 'Search',
  addContactTitle: 'Start a conversation',
  addContactBody: 'Enter an account ID or a @handle.',
  accountIdOrHandle: 'Account ID or @handle',
  start: 'Start',

  messagePlaceholder: 'Message',
  send: 'Send',
  encryptedNotice: 'Messages in this chat are end-to-end encrypted.',
  sending: 'Sending',
  sent: 'Sent',
  delivered: 'Delivered',
  read: 'Read',
  failed: 'Not delivered',
  typing: 'typing…',
  privacyHeading: 'What contacts are told',
  readReceiptsLabel: 'Read receipts',
  readReceiptsHelp:
    'Tells the sender when you opened the conversation. Turning this off also hides theirs — you cannot see when they read without saying when you did.',
  typingIndicatorsLabel: 'Typing indicators',
  typingIndicatorsHelp:
    'Tells the other end when you are at the keyboard. Off is also off in both directions. Delivery ticks are not affected: those say the message reached a phone, not that anyone looked at it.',
  today: 'Today',
  yesterday: 'Yesterday',

  verifyTitle: 'Verify this contact',
  verifyBody:
    'Compare these numbers with your contact in person or over a call you trust. If they match, nobody is intercepting this conversation.',
  safetyNumber: 'Safety number',
  markVerified: 'They match',
  verified: 'Verified',
  notVerified: 'Not verified',
  scanQr: 'Scan their code',

  identityChangedTitle: 'This contact’s security code changed',
  identityChangedBody:
    'This usually means they reinstalled the app or switched device. It can also mean someone is intercepting your messages. Sending is paused until you check.',
  identityChangedAction: 'Compare safety numbers',
  sendingBlocked: 'Sending is paused',

  settings: 'Settings',
  yourAccountId: 'Your account ID',
  yourHandle: 'Your handle',
  setHandle: 'Choose a handle',
  copied: 'Copied',
  aboutSecurity: 'How Tildra protects you',
  notAudited:
    'Tildra is pre-alpha and has not been independently audited. Don’t rely on it yet for anything where being wrong has consequences.',
  signOut: 'Sign out',

  errorNetwork: 'Can’t reach the server. Check your connection.',
  errorNoDevices: 'That account has no devices registered yet.',
  errorGeneric: 'Something went wrong.',
  serverSaid: 'The server said:',
  errorTransparency:
    'This server’s key transparency log did not check out, so the lookup was refused.',
  errorSplitView:
    'This server showed you and someone else different key transparency logs. That should never happen and may mean your messages are being intercepted. Verify safety numbers before continuing.',
  dismiss: 'Dismiss',
  newGroup: 'New group',
  groupNameLabel: 'Group name',
  groupNamePlaceholder: 'Book club',
  groupMembersLabel: 'Who is in it',
  groupMembersHelp:
    'Only people you have already messaged. A group key travels over the conversation you already have with someone, so there has to be one.',
  groupCreate: 'Create the group',
  groupNoContacts: 'Message somebody first, then you can put them in a group.',
  groupBody:
    'Everyone in the group gets their own copy of the key, encrypted to them. The server sees a count of envelopes and nothing else — not the name, not who is in it.',
  groupMembers: 'Members',
  groupAdd: 'Add someone',
  groupRemove: 'Remove',
  groupRemoveBody:
    'Removing someone gives everyone still here a new key. They keep what was said while they were in the group and can read nothing sent after.',
  groupYou: 'You',
  callAudio: 'Call',
  callVideo: 'Video call',
  callRinging: 'Ringing…',
  callIncoming: 'Incoming call',
  callConnecting: 'Connecting…',
  callAnswer: 'Answer',
  callDecline: 'Decline',
  callHangUp: 'Hang up',
  callMute: 'Mute',
  callUnmute: 'Unmute',
  callVerified: 'Verified — the media is pinned to the key you checked.',
  callUnverified:
    'You have not verified this person\u2019s safety number. The call is encrypted and bound to whatever key the server gave you for them, which is not the same as knowing who they are.',
  callKeyChanged:
    'This contact\u2019s key changed and you have not confirmed why. Do not treat this call as private until you have.',
  callNoRelay:
    'No relay is configured, so this call needs a direct path between the two devices and may not connect.',
  retry: 'Try again',
  cancel: 'Cancel',
  copy: 'Copy',
  done: 'Done',
};

const tr: Strings = {
  appName: 'Tildra',

  welcomeTitle: 'Kim olduğunuzu sormayan mesajlaşma',
  welcomeBody:
    'Her sohbet varsayılan olarak uçtan uca şifreli. Telefon numarası yok, e-posta yok — hesabınız bu cihazda duran bir anahtar.',
  createAccount: 'Hesap oluştur',
  creatingAccount: 'Anahtarlar üretiliyor…',
  deviceNameLabel: 'Bu cihaza bir ad verin',
  deviceNamePlaceholder: 'örn. Telefonum',
  deviceNameHelp:
    'Bu ad sunucuda saklanır; cihazlarınızı size listeleyebilmek için. Kendinizi değil, telefonu adlandırın.',
  yourNameLabel: 'Adınız',
  yourNamePlaceholder: 'İnsanlar size nasıl seslensin',
  yourNameHelp:
    'Bunu yalnızca konuştuğunuz kişiler görür. Onlara şifreli olarak gönderilir — sunucu adınızı ve fotoğrafınızı hiçbir zaman saklamaz.',
  aboutLabel: 'Hakkında',
  aboutPlaceholder: 'Kendinizle ilgili bir satır',
  changePhoto: 'Fotoğraf seç',
  removePhoto: 'Fotoğrafı kaldır',
  save: 'Kaydet',
  profileSaved: 'Kaydedildi',
  profile: 'Profil',
  linkDevice: 'Cihaz ekle',
  linkDeviceBody:
    'Yeni cihazda “Cihaz ekle”yi seçin ve orada görünen kodu buraya yapıştırın. Sonra devam etmeden önce altı hanenin iki ekranda da aynı olduğunu kontrol edin.',
  linkShowCode: 'Bu cihazın kodu',
  linkScanCode: 'Yeni cihazın kodunu yapıştırın',
  linkPairingCode: 'Eşleştirme kodu',
  linkConfirm: 'Haneler aynı',
  linkWaiting: 'Diğer cihazınızda onay bekleniyor…',
  linkDone: 'Cihaz eşleştirildi',
  joinExisting: 'Bu cihazı zaten sahip olduğum bir hesaba ekle',
  joinTitle: 'Bu cihazı ekle',
  joinBody:
    'Bu cihaz kendi anahtarını alır. Aşağıdaki kodu zaten oturum açmış bir cihaza gösterin, sonra devam etmeden önce altı hanenin iki ekranda da aynı olduğunu kontrol edin.',
  joinStart: 'Kodumu göster',
  joinShowThis: 'Bunu diğer cihazınıza gösterin',
  joinCompare:
    'Her iki ekran da bu altı haneyi göstermeli. Farklılarsa durun — iki cihazınızın arasına bir şey girmiş demektir.',
  scan: 'Kod tara',
  scanHint: 'Kamerayı diğer ekrandaki koda doğrultun',
  scanOrPaste: 'ya da yapıştırın',
  cameraPermissionTitle: 'Kamera erişimi',
  cameraPermissionBody:
    'Tildra kodu diğer ekrandan okur. Hiçbir şey kaydedilmez ve hiçbir şey yüklenmez.',
  cameraPermissionGrant: 'Kameraya izin ver',
  cameraPermissionDenied:
    'Sistem ayarlarınızda Tildra için kamera kapalı. Bunun yerine kodu yapıştırabilirsiniz.',
  verifyScanTitle: 'Kodlarını tarayın',
  verifyScanMatch: 'Doğrulandı. Doğru cihazla konuşuyorsunuz.',
  verifyScanMismatch:
    'Bu kod bu konuşmayla eşleşmiyor. Nedenini öğrenmeden devam etmeyin — anahtar değişimi tam olarak böyle görünür.',
  attachPhoto: 'Fotoğraf gönder',
  attachment: 'Ek dosya',
  attachmentFailed: 'Bu ek dosya yüklenemedi.',
  recordVoice: 'Sesli mesaj için basılı tutun',
  recording: 'Kaydediliyor…',
  play: 'Oynat',
  pause: 'Durdur',
  recoveryTitle: 'Kurtarma kelimelerinizi yazın',
  recoveryBody:
    'Bu 24 kelime hesabınıza dönmenin tek yolu. Sizin için sıfırlayamayız — sunucuda sıfırlanacak bir şey yok. Fiziksel bir yerde saklayın.',
  recoveryConfirm: 'Yazdım',
  recoveryWarning:
    'Bu kelimeleri elinde tutan herkes sizsiniz. Tam olarak kilidi açık bu telefon kadar güçlüler — bir yedek kodu değil, hesabın kendisi.',
  recoveryWritten: 'Güvenli bir yerde duruyor',
  recoverTitle: 'Hesabı kurtar',
  recoverBody:
    '24 kelimeyi yazın. Yazarken kontrol edilir, yani yanlış bir kelime başka bir şey olmadan önce belli olur.',
  recoverPlaceholder: 'birinci kelime, ikinci kelime, …',
  recoverAction: 'Kurtar',
  recoverEntry: 'Kurtarma kelimelerim var',
  noPhoneNeeded: 'Telefon numarası gerekmiyor',

  chats: 'Sohbetler',
  noChatsTitle: 'Henüz sohbet yok',
  noChatsBody: 'Hesap kimliğinizi biriyle paylaşın ya da onunkini ekleyip başlayın.',
  newChat: 'Yeni sohbet',
  searchPlaceholder: 'Ara',
  addContactTitle: 'Sohbet başlat',
  addContactBody: 'Bir hesap kimliği veya @kullanıcıadı girin.',
  accountIdOrHandle: 'Hesap kimliği veya @kullanıcıadı',
  start: 'Başlat',

  messagePlaceholder: 'Mesaj',
  send: 'Gönder',
  encryptedNotice: 'Bu sohbetteki mesajlar uçtan uca şifreli.',
  sending: 'Gönderiliyor',
  sent: 'Gönderildi',
  delivered: 'İletildi',
  read: 'Okundu',
  failed: 'İletilemedi',
  typing: 'yazıyor…',
  privacyHeading: 'Kişilere ne söyleniyor',
  readReceiptsLabel: 'Okundu bilgisi',
  readReceiptsHelp:
    'Sohbeti ne zaman açtığını gönderene söyler. Kapatınca karşı tarafınki de görünmez — kendi okuduğunu söylemeden onunkini göremezsin.',
  typingIndicatorsLabel: 'Yazıyor göstergesi',
  typingIndicatorsHelp:
    'Klavyede olduğunu karşı tarafa söyler. Kapalıysa iki yönde de kapalıdır. İletim tikleri etkilenmez: onlar mesajın bir telefona ulaştığını söyler, birinin baktığını değil.',
  today: 'Bugün',
  yesterday: 'Dün',

  verifyTitle: 'Bu kişiyi doğrulayın',
  verifyBody:
    'Bu numaraları kişiyle yüz yüze ya da güvendiğiniz bir aramada karşılaştırın. Aynıysa bu konuşmayı kimse dinlemiyor.',
  safetyNumber: 'Güvenlik numarası',
  markVerified: 'Aynılar',
  verified: 'Doğrulandı',
  notVerified: 'Doğrulanmadı',
  scanQr: 'Kodunu tara',

  identityChangedTitle: 'Bu kişinin güvenlik kodu değişti',
  identityChangedBody:
    'Bu genelde uygulamayı yeniden kurduğu ya da cihaz değiştirdiği anlamına gelir. Ama birinin mesajlarınızı araya girip okuduğu anlamına da gelebilir. Siz kontrol edene kadar gönderim duraklatıldı.',
  identityChangedAction: 'Güvenlik numaralarını karşılaştır',
  sendingBlocked: 'Gönderim duraklatıldı',

  settings: 'Ayarlar',
  yourAccountId: 'Hesap kimliğiniz',
  yourHandle: 'Kullanıcı adınız',
  setHandle: 'Kullanıcı adı seçin',
  copied: 'Kopyalandı',
  aboutSecurity: 'Tildra sizi nasıl koruyor',
  notAudited:
    'Tildra ön-alfa aşamasında ve bağımsız olarak denetlenmedi. Yanılmanın sonuç doğuracağı işler için henüz güvenmeyin.',
  signOut: 'Çıkış yap',

  errorNetwork: 'Sunucuya ulaşılamıyor. Bağlantınızı kontrol edin.',
  errorNoDevices: 'Bu hesabın kayıtlı cihazı yok.',
  errorGeneric: 'Bir şeyler ters gitti.',
  serverSaid: 'Sunucu şunu bildirdi:',
  errorTransparency:
    'Bu sunucunun anahtar şeffaflık kaydı doğrulanamadı, arama reddedildi.',
  errorSplitView:
    'Bu sunucu size ve bir başkasına farklı anahtar şeffaflık kayıtları gösterdi. Bu asla olmamalı ve mesajlarınızın araya girilerek okunduğu anlamına gelebilir. Devam etmeden önce güvenlik numaralarını doğrulayın.',
  dismiss: 'Kapat',
  newGroup: 'Yeni grup',
  groupNameLabel: 'Grup adı',
  groupNamePlaceholder: 'Kitap kulübü',
  groupMembersLabel: 'Kimler var',
  groupMembersHelp:
    'Yalnızca daha önce mesajlaştığınız kişiler. Grup anahtarı, zaten var olan konuşma üzerinden gider; yani önce bir konuşma olmalı.',
  groupCreate: 'Grubu oluştur',
  groupNoContacts: 'Önce birine mesaj atın, sonra onu bir gruba ekleyebilirsiniz.',
  groupBody:
    'Gruptaki herkes anahtarın kendisine şifrelenmiş kopyasını alır. Sunucu yalnızca kaç zarf gittiğini görür — adı değil, kimlerin olduğunu değil.',
  groupMembers: 'Üyeler',
  groupAdd: 'Birini ekle',
  groupRemove: 'Çıkar',
  groupRemoveBody:
    'Birini çıkarmak, kalan herkese yeni bir anahtar verir. Çıkarılan kişi gruptayken söylenenleri saklar, sonrasında gönderilen hiçbir şeyi okuyamaz.',
  groupYou: 'Siz',
  callAudio: 'Ara',
  callVideo: 'Görüntülü ara',
  callRinging: 'Çalıyor…',
  callIncoming: 'Gelen arama',
  callConnecting: 'Bağlanıyor…',
  callAnswer: 'Cevapla',
  callDecline: 'Reddet',
  callHangUp: 'Kapat',
  callMute: 'Sesi kapat',
  callUnmute: 'Sesi aç',
  callVerified: 'Doğrulandı — medya, kontrol ettiğiniz anahtara bağlı.',
  callUnverified:
    'Bu kişinin güvenlik numarasını doğrulamadınız. Arama şifreli ve sunucunun size verdiği anahtara bağlı; bu, karşınızdakinin kim olduğunu bilmekle aynı şey değil.',
  callKeyChanged:
    'Bu kişinin anahtarı değişti ve nedenini onaylamadınız. Onaylayana kadar bu aramayı gizli saymayın.',
  callNoRelay:
    'Yapılandırılmış röle yok; bu arama iki cihaz arasında doğrudan bir yol gerektiriyor ve bağlanmayabilir.',
  retry: 'Tekrar dene',
  cancel: 'Vazgeç',
  copy: 'Kopyala',
  done: 'Tamam',
};

const LOCALES: Record<Locale, Strings> = { en, tr };

/**
 * Own keys only.
 *
 * This was `value in LOCALES`, which walks the prototype chain: `constructor`,
 * `toString`, `hasOwnProperty` and `__proto__` all answered true, and this is a
 * type guard, so TypeScript then treated those strings as a `Locale`. Feeding
 * one to `strings` returned a function or `Object.prototype` instead of a
 * table, and every label in the app rendered as `undefined` — with the compiler
 * satisfied throughout, because the guard had said so.
 *
 * Nothing reaches it that way today: the only caller is `resolveLocale`, and
 * the only tag comes from `Localization.getLocales()`, which returns real
 * BCP-47. The defect is that an exported guard is wrong for anyone who later
 * points it at a stored preference, a language picker or a deep link.
 */
export function isSupportedLocale(value: string): value is Locale {
  return Object.prototype.hasOwnProperty.call(LOCALES, value);
}

/**
 * Resolve a platform locale tag ("tr-TR", "en_GB") to one we ship.
 * Falls back to English rather than showing raw keys.
 */
export function resolveLocale(tag: string | undefined | null): Locale {
  if (!tag) return 'en';
  const base = tag.toLowerCase().split(/[-_]/)[0];
  return isSupportedLocale(base) ? base : 'en';
}

/**
 * The table for a locale, and never `undefined`.
 *
 * The parameter is typed, so in a compiling program the fallback is dead code.
 * It is here because the guard above was wrong once and the compiler believed
 * it: the failure was not an exception anyone could trace, it was every string
 * in the interface silently becoming `undefined`. English is a worse answer
 * than the user's own language and a much better one than a blank app.
 *
 * It goes through the same guard rather than `?? en`, which was the first
 * attempt and did not work: `LOCALES['constructor']` is the `Object` function,
 * which is perfectly truthy, so the fallback never fired for the one input it
 * existed to catch. One definition of "is a locale", used by both.
 */
export function strings(locale: Locale): Strings {
  return isSupportedLocale(locale) ? LOCALES[locale] : en;
}

export const availableLocales = Object.keys(LOCALES) as Locale[];
