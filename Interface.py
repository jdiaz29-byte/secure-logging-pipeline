import sys
# add an import BehindTheScenes as BTS or
# from BehindTheScenes import BTS as BTS based on how its written
import SuccessfulCase
import FailedCase

def main():
    print("Welcome to the Project!")
    print("========================================")
    print("Please select an option from the list below:")
    print("[S] Run Successful Case")
    print("[F] Run Failed Case")
    print("[E] Exit")
    choice = input("Enter your choice: ").strip().upper()
    
    if choice == "S":
        SuccessfulCase.run()

    elif choice == "F":
        FailedCase.run()

    elif choice == "E":
        print("Exiting the program.")
        sys.exit()

    else:
        print("Invalid choice. Please enter S, F, or E.")

if __name__ == "__main__":
    main()