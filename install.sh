make clean
if make; then
  su -c "echo \"Stopping Apache...\";/etc/init.d/apache2 stop;echo \"Wait for 3 seconds...\";sleep 3;echo \"Installing module...\";make install;echo \"Starting Apache...\";/etc/init.d/apache2 start"
fi
