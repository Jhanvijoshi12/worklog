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