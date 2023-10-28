FROM php:8.2-fpm

RUN apt-get update
RUN apt-get install -y libpq-dev
RUN apt-get install -y zlib1g-dev libzip-dev libpng-dev
#RUN apt-get install -y libfreetype6-dev libjpeg62-turbo-dev libgd-dev libsqlite3-dev
RUN docker-php-ext-configure pgsql -with-pgsql=/usr/local/pgsql
RUN #docker-php-ext-configure gd --with-jpeg=/usr/include/ --with-freetype=/usr/include/
RUN #docker-php-ext-install gd

RUN docker-php-ext-install zip
RUN docker-php-ext-install pdo_pgsql

WORKDIR /var/www/html/auth-authentication

RUN chown -R $(whoami) $(pwd)

RUN curl -sS https://getcomposer.org/installer | php -- --install-dir=/usr/local/bin --filename=composer