from threading import Thread

counter = 0

def increment_counter():
    global counter
    for _ in range(1000000):
        counter += 1

def decrement_counter():
    global counter
    for _ in range(1000000):
        counter -= 1
        
def main():
    global counter
    counter = 0

    # Create threads
    thread1 = Thread(target=increment_counter)
    thread2 = Thread(target=decrement_counter)

    # Start threads
    thread1.start()
    thread2.start()

    # Wait for both threads to finish
    thread1.join()
    thread2.join()

    print(f"Final counter value: {counter}")

if __name__ == "__main__":
    main()