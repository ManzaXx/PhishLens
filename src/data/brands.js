// Marcas suplantadas con frecuencia y sus dominios oficiales.
// `keywords` se buscan en el nombre visible del remitente; `domains` son los legítimos.
// `ccTLD: true` acepta también las variantes por país (amazon.fr, google.co.uk...).
export const BRANDS = [
  { name: 'PayPal', keywords: ['paypal'], domains: ['paypal.com', 'paypal.es', 'paypal.me'], ccTLD: true },
  { name: 'Amazon', keywords: ['amazon'], domains: ['amazon.com', 'amazon.es', 'amazon.co.uk', 'amazon.de', 'amazonaws.com'], ccTLD: true },
  { name: 'Microsoft', keywords: ['microsoft', 'outlook', 'office 365', 'office365', 'microsoft 365'], domains: ['microsoft.com', 'outlook.com', 'office.com', 'live.com', 'office365.com', 'microsoftonline.com', 'hotmail.com', 'msn.com', 'office.net', 'sharepoint.com', 'onmicrosoft.com'], ccTLD: true },
  { name: 'Apple', keywords: ['apple', 'icloud'], domains: ['apple.com', 'icloud.com', 'me.com'], ccTLD: true },
  { name: 'Google', keywords: ['google', 'gmail'], domains: ['google.com', 'google.es', 'gmail.com', 'youtube.com', 'googlemail.com', 'gstatic.com'], ccTLD: true },
  { name: 'Netflix', keywords: ['netflix'], domains: ['netflix.com'] },
  { name: 'Correos', keywords: ['correos'], domains: ['correos.es', 'correos.com'] },
  { name: 'DHL', keywords: ['dhl'], domains: ['dhl.com', 'dhl.es', 'dhl.de'], ccTLD: true },
  { name: 'Santander', keywords: ['santander'], domains: ['bancosantander.es', 'santander.com', 'santander.es'] },
  { name: 'BBVA', keywords: ['bbva'], domains: ['bbva.es', 'bbva.com'] },
  { name: 'CaixaBank', keywords: ['caixabank', 'la caixa'], domains: ['caixabank.es', 'caixabank.com'] },
  { name: 'Agencia Tributaria', keywords: ['agencia tributaria', 'hacienda', 'aeat'], domains: ['agenciatributaria.gob.es', 'agenciatributaria.es'] },
  { name: 'Meta', keywords: ['facebook', 'meta'], domains: ['facebook.com', 'facebookmail.com', 'meta.com'] },
  { name: 'Instagram', keywords: ['instagram'], domains: ['instagram.com', 'mail.instagram.com'] },
  { name: 'LinkedIn', keywords: ['linkedin'], domains: ['linkedin.com'] },
];
