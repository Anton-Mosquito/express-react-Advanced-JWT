import nodemailer from "nodemailer";

class MailService {
  transporter: nodemailer.Transporter;

  constructor() {
    this.transporter = nodemailer.createTransport({
      service: process.env.SMTP_SERVICE,
      auth: {
        type: "OAuth2",
        user: process.env.GOOGLE_CLIENT,
        clientId: process.env.GOOGLE_CLIENT_ID,
        clientSecret: process.env.GOOGLE_CLIENT_SECRET,
        refreshToken: process.env.GOOGLE_REFRESH_TOKEN,
      },
    });
  }

  async sendActivationMail(to: string, link: string) {
    try {
      await this.transporter.sendMail({
        from: process.env.GOOGLE_CLIENT,
        to,
        subject: `Account activation ${process.env.API_URL || ""}`,
        text: `Activate: ${link}`,
        html: `
        <div>
            <h1>For activation go to the link</h1>
            <a href="${link}">${link}</a>
        </div>
      `,
      });
    } catch (err) {
      // Log error but do not throw — registration flow should not fail because of email issues
      console.error("Failed to send activation email:", err);
    }
  }
}

export default new MailService();
