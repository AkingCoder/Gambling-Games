#include <stdio.h>
#include<time.h>
#include <stdlib.h>
#include "sqlite3.h"
#include <string.h>
#include "auth.h"

/* DATABASE MANGMENT */

typedef struct{
    int logIn;
    int user_id;
    char user_name[64];
} Session;

void accMenu(Session *session);

float checkBalance(int id){
    sqlite3 *db;
    float balance = 0.0;
    
    int db_conn = sqlite3_open("gamblingGames.db", &db);
    if (db_conn != SQLITE_OK) {
        printf("Cannot open database: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return -1.0;
    }

    const char *sql =
        "SELECT balance FROM users WHERE id = ?;";
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);

    if(rc == SQLITE_OK){
        rc = sqlite3_bind_int(stmt,1,id);
    }
    if(rc == SQLITE_OK){
        rc = sqlite3_step(stmt);
    }



    if(rc == SQLITE_ROW){
        balance = sqlite3_column_double(stmt,0);
        // printf("Current Balance : %.2f\n",balance);
    }
    else{
        printf("Error occurred: %s\n", sqlite3_errmsg(db));
    }

    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return balance;
}

int updateBalance(int id,float amount){
    sqlite3 *db;
    sqlite3_stmt *statement;

    int db_conn = sqlite3_open("gamblingGames.db", &db);
    if (db_conn != SQLITE_OK) {
        printf("Cannot open database: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return 1;
    }

    const char *sql = "UPDATE users SET balance = balance + ? WHERE id = ?;";

    db_conn = sqlite3_prepare_v2(db,sql,-1,&statement,NULL);

    if(db_conn == SQLITE_OK){
        db_conn = sqlite3_bind_double(statement,1,amount);
    }
    if(db_conn == SQLITE_OK){
        db_conn = sqlite3_bind_int(statement,2,id);
    }
    if(db_conn == SQLITE_OK){
        db_conn = sqlite3_step(statement);
    }

    if(db_conn != SQLITE_DONE){
        printf("Your reward is not successfully deposited in wallet\n");
    }
    else{
        printf("Your reward Rs.%.2f is successfully deposited in wallet\n",amount);
    }
    sqlite3_finalize(statement);
    sqlite3_close(db);
    return 0;
}

int depMoney(int id){
    sqlite3 *db;
    sqlite3_stmt *statement;
    float amount = 0.0;
    int db_conn = sqlite3_open("gamblingGames.db", &db);
    if (db_conn != SQLITE_OK) {
        printf("Cannot open database: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return 1;
    }
    printf("Enter amount(in rupees) : ");
    scanf("%f",&amount);
    getchar();
    printf("Press enter to do transaction");
    getchar();
    printf("\n");

    if(amount < 0){
        printf("Enter correct amount");
        sqlite3_close(db);
        return 1;
    }

    const char *sql = "UPDATE users SET balance = balance + ? WHERE id = ?;";

    db_conn = sqlite3_prepare_v2(db,sql,-1,&statement,NULL);

    if(db_conn == SQLITE_OK){
        db_conn = sqlite3_bind_double(statement,1,amount);
    }
    if(db_conn == SQLITE_OK){
        db_conn = sqlite3_bind_int(statement,2,id);
    }
    if(db_conn == SQLITE_OK){
        db_conn = sqlite3_step(statement);
    }

    if(db_conn != SQLITE_DONE){
        printf("Amount is not deposited succuessfuly\n");
    }
    else{
        printf("Amount Rs.%.2f is deposited successfully\n",amount);
    }
    sqlite3_finalize(statement);
    sqlite3_close(db);
    return 0;
}



/* DATABASE MANGMENT */

/*AUTHANTICATION*/



void userReg(Session *session){

    sqlite3 *db;
    sqlite3_open("gamblingGames.db", &db);
    auth_init(db);

    char user[64], pass[128];
    int uid;

    printf("Username: "); 
    scanf("%s",&user);

    printf("Password: "); 
    scanf("%s",&pass); 

    int rc = auth_register(db, user, pass);
    if(rc == 0){
        int uid = (int)sqlite3_last_insert_rowid(db);
        session->user_id = uid;
        session->logIn = 1;
        snprintf(session->user_name, sizeof(session->user_name), "%s", user);
        printf("Registered.\n");
    }
    else if (rc == -2) printf("Username taken.\n");
    else               printf("Register error.\n");   
    return ; 
}

void userLogIn(Session *session){
    sqlite3 *db;
    int db_conn = sqlite3_open("gamblingGames.db", &db);
    if (db_conn != SQLITE_OK) {
        printf("Cannot open database: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return;
    }

    if (auth_init(db) != 0) {
        printf("Auth initialization error");
        sqlite3_close(db);
        return;
    }

    AuthUser *users = NULL;
    size_t user_count = 0;
    int choice = 0;


    if (auth_get_all_users(db, &users, &user_count) == 0) {
        printf("+-----------------------------------+\n");
        printf("|            Accounts               |\n");
        printf("+-----------------------------------+\n");
        if(session->logIn == 1){
            printf("|  user: %s       wallet: %.2f   |\n",session->user_name,checkBalance(session->user_id));
            printf("|                                      |\n");
        }

        for (size_t i = 0; i < user_count; i++) {
            printf("|  %d. %s                           |\n",users[i].id,users[i].username);
        }
        printf("+-----------------------------------+\n");
        printf("|  Enter your choice: ");
        fflush(stdout);
        scanf("%d", &choice);
        
    } else {
        printf("Could not read users.\n");
        return;
    }
    
    char pass[128];
    int uid;
    
    printf("Password: "); 
    scanf("%127s", pass);
    
    int rc = auth_login(db, users[choice-1].username, pass, &uid);
    sqlite3_close(db);

    if (rc != 0) {
        printf("Invalid username or password.\n");
        return ;
    }
    printf("Setting user session details");
    session->logIn = 1;
    session->user_id = uid;
    snprintf(session->user_name, sizeof(session->user_name), "%s",
             users[choice - 1].username);
    free(users);
    return ;
}

/*AUTHANTICATION*/

static void sleep_ms(long ms) {
    struct timespec ts;
    ts.tv_sec  = ms / 1000;
    ts.tv_nsec = (ms % 1000) * 1000000L;
    nanosleep(&ts, NULL);
}

void loading_dots(char *msg, int dots, int delay_ms) {
    printf("%s", msg);
    fflush(stdout);
    for (int i = 0; i < dots; i++) {
        sleep_ms(delay_ms);
        putchar('.');
        fflush(stdout);
    }
    putchar('\n');
}

void loading(){
    char *rolls[] = {
    "Rolling", "Spinning", "Let's see you luck", "Revealing", "Consulting fate"
    };
    char *pick = rolls[rand() % 5];
    loading_dots(pick, rand() % 5, 400);
}

int rangeRushGame(Session *session);

void walletMenu(Session *session){
    int AccChoice = 0;
    do{
        printf("+-----------------------------------+\n");
        printf("|              Wallet               |\n");
        printf("+-----------------------------------+\n");
        if(session->logIn == 1){
            printf("|  user: %s       wallet: %.2f   |\n",session->user_name,checkBalance(session->user_id));
            printf("|                                      |\n");
        }
        printf("|  1. Deposite                      |\n");
        printf("|  2. Check Balance                 |\n");
        printf("|  3. Exit                          |\n");
        printf("+-----------------------------------+\n");
        printf("|  Enter your choice: ");
        fflush(stdout);       
        scanf("%d", &AccChoice);

        switch (AccChoice)
        {
        case 1:
            depMoney(session->user_id);
            break;
            
        case 2:{
            float balance = checkBalance(session->user_id);
            printf("%.2f",balance);
            break;
        }
        case 3:
            break;
        }
    } while (AccChoice != 3);
    printf("\n");
}

void mainMenu(Session *session){
    int choice = 0;
    do{
        printf("+--------------------------------------+\n");
        printf("|         Gambling Games               |\n");
        printf("+--------------------------------------+\n");
        printf("|          MAIN MENU                   |\n");
        printf("+--------------------------------------+\n");
        if(session->logIn == 1){
            printf("|  user: %s       wallet: %.2f   |\n",session->user_name,checkBalance(session->user_id));
            printf("|                                      |\n");
        }
        printf("|  1. Games                            |\n");
        printf("|  2. Wallet                           |\n");
        printf("|  3. Create account / Existing account|\n");
        printf("|  4. Settings                         |\n");
        printf("|  5. Exit                             |\n");
        printf("+--------------------------------------+\n");
        printf("|  Enter your choice: ");
        fflush(stdout);
        scanf("%d",&choice);
        switch(choice){
            case 1:{
                if(session->logIn == 1){
                    rangeRushGame(session);
                }else{
                    accMenu(session);
                }
                break;
            }
            case 2:{
                if(session->logIn == 1){
                    walletMenu(session);
                }else{
                    accMenu(session);
                }
                break;
            }
            case 3:
                accMenu(session);
                break; 
            case 4:
                printf("Settings Menu");
                break;
            case 5:
                printf("Exit");
                break;
            default:
                printf("\nInvalid Choice!\n\n");
                break;           
        }
    }while(choice != 6);
}

void accMenu(Session *session){
    int choice = 0;
    do{
        printf("+--------------------------------------+\n");
        printf("|            Manage Account            |\n");
        printf("+--------------------------------------+\n");
        // printf("%s",session->user_name);
        if(session->logIn == 1){
            printf("|  user: %s       wallet: %.2f   |\n",session->user_name,checkBalance(session->user_id));
            printf("|                                      |\n");
        }
        printf("|                                      |\n");
        printf("|  1. Create new account               |\n");
        printf("|  2. Existing account                 |\n");
        printf("|  3. Exist                            |\n");
        printf("+--------------------------------------+\n");
        printf("|  Enter your choice: ");
        fflush(stdout);
        scanf("%d",&choice);
        switch(choice){
            case 1:
            userReg(session);
            break;
            case 2: {
                userLogIn(session);
                if(session->logIn == 0){
                    userReg(session);
                    printf("%s",session->user_name);
                }
                break;
            }
            case 3:
                printf("Exit");
                break;
            default:
                printf("\nInvalid Choice!\n\n");
                break;           
        }
    }while(choice != 3);
}

int randNumGen(int min,int max){
    srand(time(NULL));
    return ((rand() % (max - min + 1)) + min);
}
int rangeRushGame(Session *session){
    int range = 10;
    int start = 0;
    double betAmount = 0;
    int end = 0;
    double multiplyer = 0;
    double winChance = 0;

    printf("\n");
    printf("  +-- NUMBER GUSSING GAME -----------+\n");
    printf("  |\n");
    printf("  | A Number Guessing Game where the player selected range\n");
    printf("  | between 1-10 and a randomly generated number is lies in your\n");
    printf("  | select range than you win the price\n");
    printf("  |\n");
    printf("  |  Range    : %d - %d\n", 1, 10);
    printf("  |\n");
    printf("  +------------------------------------+\n\n");
        
    do{ 
        printf("Starting number = ");
        scanf("%d",&start);

        printf("Ending number = ");
        scanf("%d",&end);
        
        if((start > end) || (start < 1 || start > 10) || (end < 1 || end > 10)){
            printf("Please enter a valid range\n");
        }
    }while((start > end) || (start < 1 || start > 10) || (end < 1 || end > 10));

    multiplyer = (double)range/((end-start)+1);
    winChance = 100.0 * (end - start + 1) / range;
    
    
    
    printf("\nRange \t Multiplyer \tWin Chance\n");
    printf(" %d-%d\t",start,end);
    printf("  %.3f\t\t",multiplyer);
    printf("   %.2f",winChance);
    

    float balance = checkBalance(session->user_id);
    printf("\n\nBet = ");
    scanf("%lf",&betAmount);

    if(betAmount > balance){
        printf("You don't have enough money");
        return 0;
    }
    else if(betAmount < 0){
        printf("Please enter valid bet");
        return 0;
    }
    


    getchar();
    printf("PRESS ENTER TO PLAY ");
    getchar();

    

    loading();

    int randNum = randNumGen(1,10);
    double reward = 0;
    if((randNum >= start) && (randNum <= end)){
        printf("%d\n",randNum);
        reward = ((double)betAmount * multiplyer) - betAmount;
        printf(">>> HIT!  Reward Earned (%.2f)\n",reward);
        updateBalance(session->user_id,reward);
    }
    else{
        printf("you loss");
        updateBalance(session->user_id,-betAmount);
    }





    return 0;

}

int colorTradingGame(){
    
}





int main(){
    Session session = {0};
    session.logIn = 0;
    session.user_id = -1;
    mainMenu(&session);
    // printf("Upper user login");
    // session = userLogIn();
    // printf("lower user login");
    // if(!session.logIn){
    //     printf("Session create error");
    //     return 1;
    // }
    printf("Done");
    rangeRushGame(&session);
    srand(time(NULL));



    return 0;
}