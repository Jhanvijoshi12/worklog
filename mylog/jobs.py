from django.core.mail import EmailMultiAlternatives
from django.template.loader import render_to_string
from django_rq import job


@job
def send_email_to_user(
        receiver_email, data, scheme, host
) -> None:
    """
    receiver_email -> user's email
    data -> User request data
    """
    try:
        title = "Register Successfully"
        message_to_user = render_to_string(
            'send_mail.html',
            {
                'user_request': data,
                'scheme': scheme,
                'host': host
            },
        )
        email_to_user = EmailMultiAlternatives(
            title,
            message_to_user,
            "Worklog Management <settings.EMAIL_HOST_USER>",
            to=[receiver_email],
        )
        email_to_user.attach_alternative(message_to_user, 'text/html')
        email_to_user.send()
    except Exception as e:
        return e


@job
def send_reset_password_email(
        user_email, data, scheme, host
) -> None:
    """
    job for sending mail when user have to reset the password.
    """
    try:
        title = "Reset Password.."
        message = render_to_string(
            'send_reset_password_link.html',
            {
                'user': data,
                'scheme': scheme,
                'host': host
            }
        )
        reset_pwd_email_to_user = EmailMultiAlternatives(
            title,
            message,
            'Work Log Management <settings.EMAIL_HOST_USER>',
            to=[user_email]
        )
        reset_pwd_email_to_user.attach_alternative(message, 'text/html')
        reset_pwd_email_to_user.send()
    except Exception as e:
        return e