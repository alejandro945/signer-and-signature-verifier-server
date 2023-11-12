from django.urls import path
from .views import RSAKeyPairView, SignFileView, VerifySignatureView

urlpatterns = [
    path('key-pair/', RSAKeyPairView.as_view(), name='generate-key-pair'),
    path('key-pair/<int:pk>/', RSAKeyPairView.as_view(), name='detail-key-pair'),
    path('sign-file/', SignFileView.as_view(), name='sign-file'),
    path('verify-signature/', VerifySignatureView.as_view(), name='verify-signature'),
]