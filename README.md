traffic capture
    
    program maps, captures network activity on a specified port 
    
    use to map simple behaviors on network, process captured data,
    identify specific hosts and supprted services.
    
    bugs/fixes: program runs yet en0 is inactive, so no packet capture; 
    when switching to en1, program hangs until keyboard quit, 
    which reveals socket connection faliure.
