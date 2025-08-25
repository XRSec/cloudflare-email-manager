export type Bindings = {
  ACCESS_TOKEN: string;
  SENDER_EMAIL: string;
  SENDER_NAME: string;
  RESEND_APIKEY: string;
  // D1 数据库绑定
  DB: D1Database;
  // R2 存储绑定（用于存放附件）
  R2: R2Bucket;
};

declare global {
  function getMiniflareBindings(): Bindings;
}
