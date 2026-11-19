# Regras de ofuscação do ReaDroid.
# O release roda com isMinifyEnabled = false; estas regras existem para o caso
# de a ofuscação ser ativada depois sem quebrar o apksig nem o BouncyCastle.

-keep class com.android.apksig.** { *; }
-keep class org.bouncycastle.** { *; }
-dontwarn org.bouncycastle.**

-keepattributes Signature,InnerClasses,EnclosingMethod
-keepattributes *Annotation*

# O parser AXML usa nomes de tags e atributos lidos do próprio APK analisado,
# não reflexão sobre classes do app — nada a preservar além das regras acima.
