# Script Runner test script
cmd("EAGLEGATE EXAMPLE")
wait_check("EAGLEGATE STATUS BOOL == 'FALSE'", 5)
