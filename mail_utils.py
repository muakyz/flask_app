import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

def send_email(recipient, subject, body):
    sender_email = "verification@waytbeta.xyz"
    sender_password = "sens58.AKYZZ"
    smtp_server = "mail.kurumsaleposta.com"
    smtp_port = 587

    try:
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()
            server.login(sender_email, sender_password)
            
            message = MIMEMultipart()
            message['From'] = sender_email
            message['To'] = recipient
            message['Subject'] = subject
            
            message.attach(MIMEText(body, 'plain', 'utf-8'))
            
            server.sendmail(sender_email, recipient, message.as_string())
            print(f"E-posta gönderildi: {recipient}")
            return True, f"E-posta gönderildi: {recipient}"
    except Exception as e:
        print(f"E-posta gönderilemedi: {recipient}. Hata: {e}")
        return False, f"E-posta gönderilemedi: {recipient}. Hata: {e}"
