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
  yourNameLabel: string;
  yourNamePlaceholder: string;
  yourNameHelp: string;
  recoveryTitle: string;
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
  failed: string;
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
  yourNameLabel: 'Your name',
  yourNamePlaceholder: 'What people should call you',
  yourNameHelp:
    'Only people you talk to see this. It is sent to them encrypted — the server never stores your name or picture.',
  recoveryTitle: 'Write down your recovery phrase',
  recoveryBody:
    'These 24 words are the only way back into your account. We cannot reset them for you — the server has nothing to reset. Store them somewhere physical.',
  recoveryConfirm: 'I’ve written it down',
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
  failed: 'Not delivered',
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
  yourNameLabel: 'Adınız',
  yourNamePlaceholder: 'İnsanlar size nasıl seslensin',
  yourNameHelp:
    'Bunu yalnızca konuştuğunuz kişiler görür. Onlara şifreli olarak gönderilir — sunucu adınızı ve fotoğrafınızı hiçbir zaman saklamaz.',
  recoveryTitle: 'Kurtarma kelimelerinizi yazın',
  recoveryBody:
    'Bu 24 kelime hesabınıza dönmenin tek yolu. Sizin için sıfırlayamayız — sunucuda sıfırlanacak bir şey yok. Fiziksel bir yerde saklayın.',
  recoveryConfirm: 'Yazdım',
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
  failed: 'İletilemedi',
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
  retry: 'Tekrar dene',
  cancel: 'Vazgeç',
  copy: 'Kopyala',
  done: 'Tamam',
};

const LOCALES: Record<Locale, Strings> = { en, tr };

export function isSupportedLocale(value: string): value is Locale {
  return value in LOCALES;
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

export function strings(locale: Locale): Strings {
  return LOCALES[locale];
}

export const availableLocales = Object.keys(LOCALES) as Locale[];
